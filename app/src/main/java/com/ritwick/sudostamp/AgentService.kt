package com.ritwick.sudostamp

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * Foreground listener. Accepts ONE client at a time and speaks AgentProtocol.
 *
 * THE FAIL-CLOSED CONTRACT -- the reason this class exists in this shape:
 *   - Any error, timeout, or cancellation writes at most SSH_AGENT_FAILURE. Never a signature.
 *   - The biometric is enforced by the TEE, so even a subverted AgentService could not
 *     produce a signature without the user's finger.
 *   - Cancel or timeout means sign() throws, we return failure, pam_rssh denies, and PAM
 *     falls through to the password prompt.
 */
class AgentService : Service() {

    companion object {
        const val TAG = "SudoStamp"
        const val PORT = 7777
        const val NOTIF_ID = 1               // the ongoing foreground notification
        const val APPROVAL_NOTIF_ID = 2      // the urgent "approve this" prompt

        /**
         * TWO channels, deliberately. Android freezes a channel's importance at creation
         * and silently ignores later attempts to change it -- so reusing one channel for
         * both the quiet "listening" notice and the urgent approval request left the
         * approval stuck at IMPORTANCE_LOW, where it may never surface. An approval prompt
         * you do not see is a failed approval.
         */
        const val CHANNEL_PERSISTENT = "sudostamp-listener"
        const val CHANNEL_APPROVAL = "sudostamp-approval"

        /** Intent action behind the notification's Deny button. */
        const val ACTION_DENY = "com.ritwick.sudostamp.DENY"

        /** How long we wait for the user to touch the sensor before denying. */
        const val APPROVAL_TIMEOUT_MS = 60_000L

        /** Between attempts to bind the port, e.g. while a previous instance's socket is
         *  still being torn down. Retrying beats stopSelf(): a listener that silently
         *  gave up looks exactly like a healthy one from the screen. */
        private const val BIND_RETRY_MS = 5_000L

        /**
         * How long one connection may hold the single worker, NOT counting time spent
         * waiting on the user. soTimeout alone bounds each read, so a LAN client trickling
         * a byte every few seconds could hold the listener forever and every real sudo
         * would queue behind it. pam_rssh sends both of its frames at once, so 30 s is
         * generous.
         */
        private const val CONNECTION_BUDGET_MS = 30_000L

        /** pam_rssh sends two frames per connection (one more per extra key it tries).
         *  Anything chattier is not pam_rssh. */
        private const val MAX_FRAMES_PER_CONNECTION = 8

        /**
         * The sign request waiting on the user. A single volatile slot is enough because
         * the listener is single-threaded -- there is nothing to queue.
         */
        @Volatile private var current: Approval? = null

        /** Unknown hosts that were denied or ignored are refused unprompted for a while:
         *  see [Cooldown]. Process-wide, like the listener. */
        private val cooldown = Cooldown(COOLDOWN_MS)

        /** Long enough to stop a prompt every few seconds, short enough that a real first
         *  setup that timed out can simply be retried. */
        private const val COOLDOWN_MS = 30_000L

        /** True while the server socket is bound and accepting. The setup screen shows
         *  THIS, not "a key exists", so a dead listener can never read as healthy. */
        @Volatile var listening = false
            private set

        /**
         * Called (on the listener thread) whenever a request is parked or resolved, or
         * the listener comes up or goes down.
         *
         * Without this, an Activity already in the foreground never learns a request
         * arrived -- onResume has already run and will not run again -- so it would sit
         * idle while the approval ticked down to a denial. It is equally how a prompt
         * whose request timed out gets taken down instead of signing into the void.
         * Same-process callback, so no IPC and no polling.
         */
        @Volatile var onChange: (() -> Unit)? = null

        fun currentRequest(): Approval? = current

        /**
         * Creates both channels (idempotent). Called up front, not when the first
         * notification posts: until a channel exists the user cannot open its settings,
         * so the Do Not Disturb override could not be granted before the first sudo --
         * which then arrived silently.
         */
        fun ensureChannels(ctx: Context) {
            val nm = ctx.getSystemService(NotificationManager::class.java)
            for ((id, important) in listOf(CHANNEL_PERSISTENT to false, CHANNEL_APPROVAL to true)) {
                nm.createNotificationChannel(
                    NotificationChannel(
                        id,
                        ctx.getString(if (important) R.string.channel_approval else R.string.channel_listener),
                        if (important) NotificationManager.IMPORTANCE_HIGH
                        else NotificationManager.IMPORTANCE_LOW
                    ).apply {
                        // Shown under each channel in system Settings, where the user decides
                        // what may interrupt them -- the one place a name alone is not enough.
                        description = ctx.getString(
                            if (important) R.string.channel_approval_desc else R.string.channel_listener_desc
                        )
                    }
                )
            }
        }

        private fun changed() {
            runCatching { onChange?.invoke() }
        }
    }

    @Volatile private var running = false
    private var server: ServerSocket? = null

    override fun onCreate() {
        super.onCreate()
        ensureChannels(this)
        // A foreground service MUST show an ongoing notification (Android 8+) or the
        // OS kills the listener; there is no way around it without losing the
        // always-on property. Keep it quiet (LOW channel) and minimal: what it is.
        // Tapping opens the app.
        val status = getString(R.string.notif_listener_title)
        val open = PendingIntent.getActivity(
            this, 1,
            Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        startForeground(
            NOTIF_ID,
            buildNotification(status, null, CHANNEL_PERSISTENT, open)
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DENY) {
            // From the approval notification: reject without opening the app at all.
            current?.deny()?.let { if (it) Log.i(TAG, "denied from the notification") }
        }
        if (!running) {
            running = true
            Thread(::acceptLoop, "agent-accept").apply { isDaemon = true }.start()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        runCatching { server?.close() }
        // Release a parked request now rather than leaving pam_rssh waiting out the full
        // approval window on a service that no longer exists.
        current?.deny()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // ------------------------------------------------------------------- accept

    private fun acceptLoop() {
        val srv = bind() ?: return
        listening = true
        changed()
        var acceptFailures = 0
        while (running) {
            try {
                srv.accept().use { s ->
                    acceptFailures = 0
                    handle(s)
                }
            } catch (e: Exception) {
                if (!running) break
                acceptFailures++
                Log.w(TAG, "connection ended: ${e.message}")
                // A single dropped connection is routine, but a run of immediate
                // failures (e.g. fd exhaustion) would otherwise spin accept() into a
                // busy loop and drain the battery -- so back off once it looks repeated.
                if (acceptFailures > 3) {
                    runCatching { Thread.sleep(1000L) }
                }
            }
        }
        listening = false
        changed()
    }

    /** Binds the listener, retrying until it works or the service is stopped. */
    private fun bind(): ServerSocket? {
        while (running) {
            try {
                return ServerSocket(PORT, 4, InetAddress.getByName("0.0.0.0")).also {
                    server = it
                    Log.i(TAG, "listening on $PORT")
                }
            } catch (e: Exception) {
                Log.e(TAG, "cannot listen on $PORT, retrying: ${e.message}")
                runCatching { Thread.sleep(BIND_RETRY_MS) }
            }
        }
        return null
    }

    private fun handle(s: Socket) {
        val client = s.inetAddress.hostAddress ?: "unknown"
        // LAN-only is enforced here, not just assumed. The socket binds every interface,
        // and some carriers hand out publicly reachable addresses on mobile data; a request
        // from the internet must not be able to post an approval prompt at all.
        if (!Net.isLan(s.inetAddress)) {
            Log.w(TAG, "refusing non-LAN client $client")
            return
        }
        val out = s.getOutputStream()
        val input = DeadlineInput(
            s, s.getInputStream(), SystemClock.elapsedRealtimeNanos() + CONNECTION_BUDGET_MS * 1_000_000
        )
        var frames = 0
        // ONE connection, MANY frames.
        //
        // pam_rssh keeps a single stream open and sends REQUEST_IDENTITIES followed by
        // SIGN_REQUEST over it (ssh_agent_auth.rs:63 reuses self.stream). Serving exactly
        // one frame and hanging up therefore broke EVERY real authentication, while still
        // passing any test client that opened a fresh connection per request -- which is
        // exactly what the earlier end-to-end check did, and why it looked like it worked.
        while (running) {
            if (++frames > MAX_FRAMES_PER_CONNECTION) {
                Log.w(TAG, "$client sent more than $MAX_FRAMES_PER_CONNECTION frames, closing")
                return
            }
            val frame = try {
                AgentProtocol.readFrame(input) ?: return   // clean EOF: client is done
            } catch (e: Exception) {
                Log.w(TAG, "read failed, closing: ${e.message}")
                return
            }
            try {
                val waited = serve(frame, out, client)
                input.deadline += waited     // the user's time is not the client's budget
            } catch (e: Exception) {
                Log.w(TAG, "request failed: ${e.message}")
                // Fail closed with a proper protocol answer where possible. pam_rssh
                // treats a FAILURE frame and a bare EOF the same way (deny), but the
                // frame is what distinguishes "the agent said no" from "the agent
                // vanished" in its logs. Never a signature.
                runCatching { AgentProtocol.writeFrame(out, AgentProtocol.failure()) }
                return
            }
        }
    }

    /** Serves exactly one request frame. Throws IOException on malformed input.
     *  Returns how long (ns) it spent waiting on the user. */
    private fun serve(frame: ByteArray, out: java.io.OutputStream, client: String): Long {
        val r = AgentProtocol.Reader(frame)

        when (r.type()) {
            AgentProtocol.SSH2_AGENTC_REQUEST_IDENTITIES -> {
                AgentProtocol.writeFrame(
                    out,
                    AgentProtocol.identitiesAnswer(SshSig.keyBlob(Keys.publicKey()), "sudostamp")
                )
                Log.i(TAG, "identities requested")
            }

            AgentProtocol.SSH2_AGENTC_SIGN_REQUEST -> {
                r.skipType()
                val keyBlob = r.blob()          // which key (we have exactly one)
                val data = r.blob()             // what to sign
                r.int32()                       // flags

                val known = KnownHosts.isKnown(this, client)
                val refusal = AgentProtocol.refusal(keyBlob, data, SshSig.keyBlob(Keys.publicKey()))
                    ?: if (cooldown.active(client, known)) "cooling down after an unapproved request" else null
                if (refusal != null) {
                    Log.w(TAG, "$refusal (from $client)")
                    AgentProtocol.writeFrame(out, AgentProtocol.failure())
                    return 0
                }

                // Hand off to the Activity for a biometric. THIS is the gate.
                val p = Approval(Keys.newSigner(), data, client, System.currentTimeMillis())
                current = p
                notifyApprovalNeeded(p)
                // Tell a foreground Activity right now. The notification alone is not
                // enough: it only reaches us if the user taps it, and an Activity that is
                // already visible will not get another onResume.
                changed()

                val waitStart = SystemClock.elapsedRealtimeNanos()
                // Keep the CPU awake for the approval window, and only for it. A dozing
                // phone suspends between packets, and suspended time does not count
                // towards a Java timeout -- so with the screen off "60 s" stretched until
                // something woke the phone, and pam_rssh, which sets no timeout of its
                // own, held sudo hanging the whole time.
                val wake = (getSystemService(Context.POWER_SERVICE) as PowerManager)
                    .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "sudostamp:approval")
                wake.acquire(APPROVAL_TIMEOUT_MS + 5_000)
                val der = try {
                    p.await(APPROVAL_TIMEOUT_MS)
                } finally {
                    if (wake.isHeld) wake.release()
                    // Resolved whichever way await ended, so a prompt still on screen is
                    // told to come down rather than collect a fingerprint for nothing.
                    p.deny()
                    current = null
                    resetNotification()
                    changed()
                }
                val waited = SystemClock.elapsedRealtimeNanos() - waitStart
                if (der == null) {
                    cooldown.unapproved(client, known)
                    // Timeout, cancel, or any failure: deny. Never guess.
                    Log.w(TAG, "denied")
                    AgentProtocol.writeFrame(out, AgentProtocol.failure())
                    return waited
                }
                AgentProtocol.writeFrame(out, AgentProtocol.signResponse(SshSig.signatureBlob(der)))
                Log.i(TAG, "signed via biometric")
                if (KnownHosts.remember(this, client)) Log.i(TAG, "$client approved for the first time")
                return waited
            }

            else -> {
                // Unreachable from pam_rssh. Refuse rather than improvise.
                Log.w(TAG, "unsupported request type ${r.type()}")
                AgentProtocol.writeFrame(out, AgentProtocol.failure())
            }
        }
        return 0
    }

    /**
     * Reads from [s] but never past [deadline] (elapsedRealtimeNanos): each read is given
     * only the time that is left. A plain soTimeout restarts on every byte, which is
     * exactly what a slow-drip client exploits.
     *
     * The clock counts time asleep. System.nanoTime does not: on a dozing phone the CPU
     * suspends between a drip client's packets, and a nanoTime budget let one hold the
     * worker for 45 s and counting -- found on the device, not by reading the code.
     */
    private class DeadlineInput(
        private val s: Socket,
        private val inner: InputStream,
        var deadline: Long,
    ) : InputStream() {
        private fun arm() {
            val leftMs = (deadline - SystemClock.elapsedRealtimeNanos()) / 1_000_000
            if (leftMs <= 0) throw SocketTimeoutException("connection budget spent")
            s.soTimeout = leftMs.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        }

        override fun read(): Int {
            arm()
            return inner.read()
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            arm()
            return inner.read(b, off, len)
        }
    }

    // ------------------------------------------------------------------ notify

    private fun notifyApprovalNeeded(p: Approval) {
        val i = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val pi = PendingIntent.getActivity(
            this, 0, i,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val deny = PendingIntent.getService(
            this, 2, Intent(this, AgentService::class.java).setAction(ACTION_DENY),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        // Separate ID and channel from the persistent notice: the foreground
        // notification must stay put, and the approval must be allowed to be loud.
        // No time in the text: the shade already shows when it arrived (setWhen below).
        mgr().notify(
            APPROVAL_NOTIF_ID,
            buildNotification(
                getString(R.string.notif_approval_title),
                getString(R.string.notif_approval_text, p.client),
                CHANNEL_APPROVAL, pi,
                // An unexpected request should be one tap to reject, without opening anything.
                Notification.Action.Builder(
                    Icon.createWithResource(this, R.drawable.ic_error), getString(R.string.deny), deny
                ).build()
            )
        )
    }

    private fun resetNotification() {
        mgr().cancel(APPROVAL_NOTIF_ID)
    }

    private fun buildNotification(
        title: String,
        text: String?,
        channelId: String,
        pi: PendingIntent? = null,
        vararg actions: Notification.Action
    ): Notification {
        val important = channelId == CHANNEL_APPROVAL
        val b = Notification.Builder(this, channelId)
        b.setContentTitle(title)
            .setSmallIcon(R.drawable.ic_stat_notify)
            // No large icon: it only repeated the small icon, which the accent already
            // tints, and took room from the requesting host.
            // Both channels are ongoing: the listener is permanent, and an approval
            // must persist in the shade until it is resolved (tapped, denied, or timed
            // out) rather than being swiped away or dismissed early.
            .setOngoing(true)
            // Only the approval shows its timestamp; the listener has no meaningful time.
            .setShowWhen(important)
            // The accent tints the small icon and actions in the shade: the one colour that
            // says "SudoStamp" at a glance among other notifications.
            .setColor(Ui.ACCENT)
            // Each notification its own group. Ungrouped, the system auto-groups an app's
            // notifications under one summary, and the approval ended up folded beneath the
            // quiet "listening" notice instead of popping up on its own.
            .setGroup(channelId)
        if (text != null) b.setContentText(text)
        if (important) {
            b.setWhen(System.currentTimeMillis())
            // Belt and braces: the service cancels it on resolution, but a notification
            // must never outlive the request it is asking about.
            b.setTimeoutAfter(APPROVAL_TIMEOUT_MS)
        }
        if (pi != null) b.setContentIntent(pi)
        actions.forEach { b.addAction(it) }
        return b.build()
    }

    private fun mgr() = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
}
