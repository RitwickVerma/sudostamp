package com.ritwick.sudostamp

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.app.NotificationManager
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.net.Uri
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import android.view.Gravity
import android.view.HapticFeedbackConstants
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.window.OnBackInvokedCallback
import android.window.OnBackInvokedDispatcher
import android.view.animation.DecelerateInterpolator
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.ritwick.sudostamp.Ui.Kind
import com.ritwick.sudostamp.Ui.Type
import com.ritwick.sudostamp.Ui.button
import com.ritwick.sudostamp.Ui.card
import com.ritwick.sudostamp.Ui.checkRow
import com.ritwick.sudostamp.Ui.column
import com.ritwick.sudostamp.Ui.divider
import com.ritwick.sudostamp.Ui.dp
import com.ritwick.sudostamp.Ui.dpf
import com.ritwick.sudostamp.Ui.field
import com.ritwick.sudostamp.Ui.icon
import com.ritwick.sudostamp.Ui.matchWrap
import com.ritwick.sudostamp.Ui.pill
import com.ritwick.sudostamp.Ui.row
import com.ritwick.sudostamp.Ui.text
import com.ritwick.sudostamp.Ui.wrap

/**
 * Four screens: setup (or onboarding, before any computer is paired), pairing, the approval,
 * and a brief result.
 *
 * THE NOTIFICATION IS THE INTERFACE. Approval starts from the notification, so the setup screen
 * has one job -- get the public key onto the host, once -- and otherwise reports, honestly,
 * whether this phone can approve anything right now: listener bound, notifications allowed,
 * battery unrestricted, key still valid. Every one of those has failed silently at some point.
 *
 * Still uses the PLATFORM BiometricPrompt, not androidx.biometric, which keeps the dependency
 * list genuinely empty -- a real property for an app in an approval path.
 *
 * An approval is the one thing this screen does on its own, and it ends by CLOSING the app
 * (see renderResult): once the TEE has signed, the signature is already on its way to the host
 * and there is nothing left to look at. The service keeps listening; this screen has no reason
 * to stay up.
 */
class MainActivity : Activity() {

    companion object {
        private const val TAG = "SudoStamp"

        /** What the user runs on the computer: the single-file installer from the latest
         *  release (scripts/bundle-host.sh), no clone needed. Its SHA-256 is on the release
         *  page; on Arch, `sudo sudostamp setup` from the AUR package does the same. */
        private const val SETUP_COMMAND =
            "curl -fsSLO https://gitlab.com/ritwick7/sudostamp/-/releases/permalink/latest/downloads/sudostamp-setup.sh\n" +
                "sudo bash sudostamp-setup.sh"
        private const val REQ_NOTIFICATIONS = 7

        /** How long the "Approved" result stays up before the app closes itself. Instant
         *  closing reads as a crash, so the success must be visible first. */
        private const val APPROVAL_FLASH_MS = 750L

        /** A denial or expiry stays a little longer, then returns to setup (no close: the
         *  user may want to look at what just happened). */
        private const val REFUSAL_FLASH_MS = 1_400L
    }

    private enum class Screen { SETUP, APPROVAL, RESULT, PAIRING }

    /** The request the approval screen is showing, so it is drawn once, not on every sync. */
    private var shownRequest = -1L

    /** The pairing state last drawn, so the screen redraws only when it changes. */
    private var shownPairing: PairingSession.View? = null

    /** While pairing: this phone advertised on the LAN as _sudostamp._tcp, so the computer
     *  can find it without being told the address. Only while the pairing screen is armed. */
    private var nsdListener: NsdManager.RegistrationListener? = null

    /** Back on the pairing screen cancels pairing instead of leaving the app. The platform
     *  callback (API 33+), not AndroidX: below that, Back finishes the activity, and
     *  onDestroy disarms. */
    private var backCallback: OnBackInvokedCallback? = null

    private fun interceptBack(on: Boolean) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val cb = backCallback
        if (on && cb == null) {
            backCallback = OnBackInvokedCallback { cancelPairing() }.also {
                onBackInvokedDispatcher.registerOnBackInvokedCallback(OnBackInvokedDispatcher.PRIORITY_DEFAULT, it)
            }
        } else if (!on && cb != null) {
            onBackInvokedDispatcher.unregisterOnBackInvokedCallback(cb)
            backCallback = null
        }
    }

    /** What the setup screen depends on. Re-rendered only when this changes, so the
     *  animated mark does not restart on every unrelated event. */
    private data class SetupState(
        val hosts: List<Host>,
        val invalidated: Set<String>,
        val canNotify: Boolean,
        val batteryOptimized: Boolean,
        val listening: Boolean,
        val address: String,
        val dnd: Dnd,
        val biometric: Int,
    )

    private var screen = Screen.SETUP

    /** The setup state last drawn. A toggle in system Settings while we were away (the
     *  notification grant, the battery exemption) or the listener coming up is picked up
     *  on the next sync instead of leaving a stale screen. */
    private var shownSetup: SetupState? = null

    /** The request the open biometric prompt is for, and the handle that takes it down.
     *  Both null when no prompt is open. */
    private var promptFor: Approval? = null
    private var promptCancel: CancellationSignal? = null

    /** Registered with the service while started; identity-checked on unregister. */
    private val onServiceChange: () -> Unit = { runOnUiThread { sync() } }

    /** Main-looper handler for the deferred close after an approval. A field (rather than
     *  View.postDelayed) so an incoming request can CANCEL the close before it fires. */
    private val ui = Handler(Looper.getMainLooper())

    /** Drives the approval screen's "N s left" once a second. Separate from [ui] so
     *  cancelling a pending close never stops the countdown, and vice versa. */
    private val tick = Handler(Looper.getMainLooper())

    /** True while the activity is resumed; a biometric prompt may only be raised from a
     *  resumed activity. Raising one while paused (split-screen, launch transition) fails
     *  instantly and would deny a request that should have waited for the user. */
    private var resumed = false

    /** Whether the notification permission has been asked for in this process; after
     *  that, a second refusal means the system will not ask again. */
    private var askedNotifications = false

    /** The request whose notification the user tapped ([AgentService.EXTRA_REQUEST]). Only
     *  that request gets the fingerprint prompt raised automatically; any other request --
     *  one that arrives while the app is already open, or right behind an approval -- waits
     *  for a tap on Approve. Raising the prompt for whatever is pending let a request timed
     *  to land just after a real one read as "sudo asked twice". */
    private var tappedRequest = -1L

    /** Computers whose key a fingerprint change destroyed. Checked on resume, not on every
     *  sync: each check opens a Keystore operation (see [Keys.state]). */
    private var invalidated: Set<String> = emptySet()

    private fun takeRequest(i: Intent?) {
        val id = i?.getLongExtra(AgentService.EXTRA_REQUEST, -1L) ?: -1L
        if (id >= 0) tappedRequest = id
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        takeRequest(intent)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AgentService.ensureChannels(this)

        takeRequest(intent)
        // Start the listener as soon as the app opens. A phone-side agent that is not
        // listening is indistinguishable from a broken setup, so never make this a tap.
        Hosts.reconcile(this)
        if (Hosts.all(this).isNotEmpty()) {
            runCatching { startForegroundService(Intent(this, AgentService::class.java)) }
        }

        // POST_NOTIFICATIONS is a RUNTIME permission from Android 13. Declaring it in the
        // manifest is not enough -- without the grant the system silently suppresses every
        // notification from this app, which means the approval prompt never appears and the
        // biometric can never be reached.
        if (!canNotify()) requestNotifications()

        // No other app may draw over the approval screen: an overlay could cover the
        // requesting computer, or dress up an unexpected request as an expected one. The
        // biometric prompt itself is system UI; this protects what surrounds it. On Android 11,
        // which has no such switch, touches through an overlay are dropped instead (frame()).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) window.setHideOverlayWindows(true)
        render()
    }

    override fun onStart() {
        super.onStart()
        // The Activity may already be in the foreground when a request lands, in which case
        // onResume has ALREADY run and will not run again -- so waiting for onResume meant a
        // visible app could sit there doing nothing while the request ticked down to a
        // denial. A same-process callback closes that gap without polling or IPC.
        AgentService.onChange = onServiceChange
    }

    override fun onStop() {
        if (AgentService.onChange === onServiceChange) AgentService.onChange = null
        // Leaving the pairing screen ends the pairing: an armed pairing nobody is watching is an
        // open door (and the screen stays on while it is up, so this is a real departure).
        if (screen == Screen.PAIRING && !isChangingConfigurations) {
            AgentService.pairing.disarm()
            AgentService.discardAbandoned(this)
            stopAdvertising()
            screen = Screen.SETUP
        }
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        invalidated = Hosts.all(this).filter { Keys.state(Keys.aliasFor(it.id)) == Keys.State.INVALIDATED }
            .map { it.id }.toSet()
        // Covers the notification-tap path (the request is already parked in the service)
        // and any setup state that changed while we were away.
        sync()
    }

    /**
     * Also re-check when the window regains focus. Settings reached from the checklist do
     * not always pause this activity (One UI can show them as a pop-up or over a split
     * screen), so onResume alone missed the user's change: the phone kept showing
     * "Silenced by Do Not Disturb" after SudoStamp had been allowed through.
     */
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) sync()
    }

    override fun onPause() {
        resumed = false
        super.onPause()
    }

    /** Nothing scheduled may outlive the activity (the flash-close included). */
    override fun onDestroy() {
        // Leaving the app ends a pairing: an armed pairing nobody is watching is an open door.
        if (isFinishing) {
            AgentService.pairing.disarm()
            AgentService.discardAbandoned(this)
        }
        interceptBack(false)
        stopAdvertising()
        ui.removeCallbacksAndMessages(null)
        tick.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    /** True when the OS will let us actually surface an approval prompt. */
    private fun canNotify(): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

    /** True when the app is still subject to Doze battery optimization. The listener must
     *  stay instant even when the phone is idle, so optimized is a warning, never a silent
     *  state. */
    private fun batteryOptimized(): Boolean =
        !(getSystemService(Context.POWER_SERVICE) as PowerManager)
            .isIgnoringBatteryOptimizations(packageName)

    private fun address() = Net.hostPort(Net.stable(), AgentService.PORT)

    private fun setupState() = SetupState(
        hosts = Hosts.all(this),
        invalidated = invalidated,
        canNotify = canNotify(),
        batteryOptimized = batteryOptimized(),
        listening = AgentService.listening,
        address = address(),
        dnd = dnd(),
        biometric = biometricStatus(),
    )

    /** BiometricManager's verdict for a strong biometric: enrolled, none enrolled, or no
     *  capable hardware. Re-read on resume, so returning from enrollment updates the screen. */
    private fun biometricStatus(): Int =
        getSystemService(BiometricManager::class.java)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)

    /** Opens the system's fingerprint enrollment (which also sets up a screen lock first if
     *  there is none). Falls back to Security settings on builds without the shortcut. */
    private fun enrollFingerprint() {
        runCatching {
            startActivity(Intent(Settings.ACTION_BIOMETRIC_ENROLL).putExtra(
                Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                BiometricManager.Authenticators.BIOMETRIC_STRONG
            ))
        }.onFailure { runCatching { startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS)) } }
    }

    /** How Do Not Disturb treats an approval right now. */
    private enum class Dnd {
        /** Off, or on and the approval breaks through. */
        CLEAR,
        /** Priority mode, and the approval channel is not allowed to override it. */
        CHANNEL_BLOCKED,
        /** On in a way no app channel can break through: total silence or alarms only. */
        MODE_BLOCKS_APPS,
    }

    /**
     * Whether Do Not Disturb is silencing approvals. The request still arrives, but silently
     * in the shade with no pop-up: found on the phone, where a sudo was approved only because
     * someone thought to open the shade.
     *
     * The channel's own override is not enough to say "clear": on the emulator the system
     * still intercepted the approval with it on, because that DND was total silence, where
     * nothing breaks through. Only the user can change either, so the screen says which.
     */
    private fun dnd(): Dnd {
        val nm = getSystemService(NotificationManager::class.java)
        return when (nm.currentInterruptionFilter) {
            NotificationManager.INTERRUPTION_FILTER_ALL,
            NotificationManager.INTERRUPTION_FILTER_UNKNOWN -> Dnd.CLEAR
            // Whether a priority mode admits app channels at all is not public API, so a
            // mode configured to block every app still reads CLEAR here. The channel
            // override is the part an app can see.
            NotificationManager.INTERRUPTION_FILTER_PRIORITY ->
                if (nm.getNotificationChannel(AgentService.CHANNEL_APPROVAL)?.canBypassDnd() == true) Dnd.CLEAR
                else Dnd.CHANNEL_BLOCKED
            else -> Dnd.MODE_BLOCKS_APPS   // NONE (total silence) or ALARMS
        }
    }

    /** Opens Do Not Disturb's own settings, for a mode that lets no app through. */
    private fun openDndSettings() {
        runCatching { startActivity(Intent(Settings.ACTION_ZEN_MODE_PRIORITY_SETTINGS)) }
            .onFailure { runCatching { startActivity(Intent(Settings.ACTION_SETTINGS)) } }
    }

    /**
     * Brings the screen and the biometric prompt in line with the service. The one place
     * that decides what is shown, called on every service event and on resume.
     *
     *   - A prompt whose request is gone (timed out, denied from the notification, reset)
     *     is taken down. Left up, it collected a fingerprint for a request the agent had
     *     already refused -- and, holding the "prompting" slot, blocked the NEXT request
     *     from ever being prompted.
     *   - A live request is prompted, but only from a resumed activity: in the launch
     *     window between onStart and onResume, or while paused in split-screen, the
     *     prompt fails instantly and would deny a request that should have waited.
     *   - A live request beats a pending close: without that, a request landing inside
     *     the previous approval's flash window would be closed on and never prompt.
     */
    private fun sync() {
        AgentService.discardAbandoned(this)
        val p = AgentService.currentRequest()?.takeIf { !it.isResolved }
        if (promptFor != null && promptFor !== p) {
            Log.i(TAG, "request resolved elsewhere: taking the prompt down")
            closePrompt()?.cancel()
        }
        when {
            p != null && promptFor == null && resumed && p.id == tappedRequest -> {
                // The user tapped THIS request's notification: straight to the fingerprint.
                ui.removeCallbacksAndMessages(null)
                tappedRequest = -1L
                renderApproval(p)
                prompt(p)
            }
            p != null && promptFor == null && !(screen == Screen.APPROVAL && shownRequest == p.id) -> {
                // Any other request is shown, and waits for a tap on Approve.
                ui.removeCallbacksAndMessages(null)
                renderApproval(p)
            }
            p == null && screen == Screen.APPROVAL ->
                if (AgentService.pairing.armed()) renderPairing() else render()
            screen == Screen.SETUP && shownSetup != setupState() -> render()
            screen == Screen.PAIRING && shownPairing != AgentService.pairing.view() -> renderPairing()
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_NOTIFICATIONS) {
            // Re-render either way: a denied permission means approvals cannot be surfaced,
            // and that must be visible on screen rather than failing silently later.
            sync()
        }
    }

    // ------------------------------------------------------------------- frame

    /**
     * Every screen sits in the same frame: a scroll view (a foldable's cover screen, or
     * landscape, is short), padded by the system bars and any display cutout because the app
     * draws edge to edge, holding a column capped at a readable width.
     */
    private fun frame(centered: Boolean, build: LinearLayout.() -> Unit): View {
        val content = Ui.Column(this).apply {
            gravity = if (centered) Gravity.CENTER else Gravity.CENTER_HORIZONTAL
            build()
        }
        val scroll = ScrollView(this).apply {
            // A touch that passed through another app's window is dropped (tapjacking).
            filterTouchesWhenObscured = true
            isFillViewport = true
            clipToPadding = false
            isVerticalScrollBarEnabled = false
            setBackgroundColor(Ui.BG)
            addView(content, FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT,
                Gravity.CENTER_HORIZONTAL
            ))
        }
        scroll.setOnApplyWindowInsetsListener { v, insets ->
            val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
            v.setPadding(bars.left + dp(24), bars.top + dp(20), bars.right + dp(24), bars.bottom + dp(24))
            insets
        }
        return scroll
    }

    private fun show(view: View) {
        setContentView(view)
        view.requestApplyInsets()
    }

    /** The mark, sized for the screen it is on. */
    private fun mark(sizeDp: Int, top: Int = 0, bottom: Int = 0) =
        FingerprintView(this, Ui.ACCENT).apply {
            layoutParams = LinearLayout.LayoutParams(dp(sizeDp), dp(sizeDp)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                topMargin = top
                bottomMargin = bottom
            }
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        }

    /** App name and tagline, the small header on setup screens. The system no longer
     *  draws a title bar, so this is the one place the name appears. */
    private fun LinearLayout.header() {
        addView(row().apply {
            addView(icon(R.drawable.ic_lock, Ui.ACCENT, 20))
            addView(text(getString(R.string.app_name), Type.TITLE).apply {
                setPadding(dp(10), 0, 0, 0)
            })
        }, matchWrap())
        addView(text(getString(R.string.tagline), Type.CAPTION, Ui.MUTED), matchWrap(top = dp(2)))
    }

    private fun LinearLayout.entrance() {
        alpha = 0f
        translationY = dpf(12f)
        animate().alpha(1f).translationY(0f).setDuration(260)
            .setInterpolator(DecelerateInterpolator()).start()
    }

    // ------------------------------------------------------------------- setup

    private fun render() {
        interceptBack(false)
        window.clearFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val state = setupState()
        Log.i(TAG, "setup: $state")
        screen = Screen.SETUP
        shownSetup = state
        tick.removeCallbacksAndMessages(null)
        show(if (state.hosts.isEmpty()) onboarding(state.biometric) else setup(state))
    }

    /** Before there is a key: what this is, the three steps, one button. */
    private fun onboarding(biometric: Int) = frame(centered = false) {
        header()
        addView(mark(176, top = dp(28), bottom = dp(8)))
        addView(text(getString(R.string.onboard_title), Type.DISPLAY, center = true), matchWrap(bottom = dp(24)))
        addView(card().apply {
            step(1, R.string.onboard_step1_title, R.string.onboard_step1_body)
            addView(divider())
            step(2, R.string.onboard_step2_title, R.string.onboard_step2_body)
            addView(divider())
            step(3, R.string.onboard_step3_title, R.string.onboard_step3_body)
        }, matchWrap())
        // The key can only be created once a strong biometric is enrolled. Say so up front
        // and offer the fix, instead of letting "Create key" fail with an exception message.
        when (biometric) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                addView(button(getString(R.string.onboard_create), Kind.PRIMARY, R.drawable.ic_key) { startPairing() },
                    matchWrap(top = dp(24)))
                addView(text(getString(R.string.onboard_footnote), Type.CAPTION, Ui.FAINT, center = true),
                    matchWrap(top = dp(12)))
            }
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                addView(button(getString(R.string.onboard_enroll), Kind.PRIMARY, R.drawable.ic_lock) { enrollFingerprint() },
                    matchWrap(top = dp(24)))
                addView(text(getString(R.string.onboard_enroll_hint), Type.CAPTION, Ui.MUTED, center = true),
                    matchWrap(top = dp(12)))
            }
            else -> addView(text(getString(R.string.onboard_unsupported), Type.BODY, Ui.WARN, center = true),
                matchWrap(top = dp(24)))
        }
        entrance()
    }

    private fun LinearLayout.step(n: Int, title: Int, body: Int) {
        addView(row().apply {
            gravity = Gravity.TOP
            addView(text(n.toString(), Type.LABEL, Ui.ACCENT).apply {
                gravity = Gravity.CENTER
                background = Ui.rounded(Ui.ACCENT_DIM, dpf(14f))
                layoutParams = LinearLayout.LayoutParams(dp(28), dp(28))
            })
            addView(column(Gravity.START).apply {
                setPadding(dp(14), dp(2), 0, 0)
                addView(text(getString(title), Type.LABEL))
                addView(text(getString(body), Type.CAPTION, Ui.MUTED), matchWrap(top = dp(2)))
            }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        }, matchWrap())
    }

    /** Status, colour, tint, icon: the one status pill on the setup screen. */
    private data class Status(val label: String, val color: Int, val dim: Int, val icon: Int)

    private fun setup(s: SetupState) = frame(centered = false) {
        header()
        addView(mark(156, top = dp(20)))

        // One status, the worst one. "Ready" only when the listener is bound AND a request
        // can actually surface.
        val st = when {
            !s.canNotify -> Status(getString(R.string.status_notifications_off), Ui.WARN, Ui.WARN_DIM, R.drawable.ic_warning)
            !s.listening -> Status(getString(R.string.status_starting), Ui.WARN, Ui.WARN_DIM, R.drawable.ic_schedule)
            s.dnd != Dnd.CLEAR -> Status(getString(R.string.status_silenced), Ui.WARN, Ui.WARN_DIM, R.drawable.ic_do_not_disturb_on)
            else -> Status(getString(R.string.status_ready), Ui.ACCENT, Ui.ACCENT_DIM, R.drawable.ic_check_circle)
        }
        addView(pill(st.label, st.color, st.dim, st.icon), wrap(top = dp(4), bottom = dp(24)))

        // What this phone needs in order to approve. Each of these failed silently once.
        addView(text(getString(R.string.section_phone), Type.OVERLINE, Ui.FAINT), matchWrap(bottom = dp(8)))
        addView(card().apply {
            addView(checkRow(
                R.drawable.ic_computer, s.listening, getString(R.string.check_listener),
                if (s.listening) getString(R.string.check_listener_ok, AgentService.PORT)
                else getString(R.string.check_listener_starting, AgentService.PORT)
            ))
            addView(divider())
            addView(checkRow(
                R.drawable.ic_notifications, s.canNotify, getString(R.string.check_notifications),
                getString(if (s.canNotify) R.string.check_notifications_ok else R.string.check_notifications_off),
                if (s.canNotify) null else getString(R.string.action_allow) to ::requestNotifications
            ))
            if (s.dnd != Dnd.CLEAR) {
                val channel = s.dnd == Dnd.CHANNEL_BLOCKED
                addView(divider())
                addView(checkRow(
                    R.drawable.ic_do_not_disturb_on, false, getString(R.string.check_dnd),
                    getString(if (channel) R.string.check_dnd_silenced else R.string.check_dnd_mode),
                    // Do Not Disturb's own page, not the channel's: Samsung's One UI has no
                    // per-channel override switch, only an "apps allowed" list there, and
                    // stock Android has the same list. One destination that works on both.
                    (if (channel) getString(R.string.action_allow) else getString(R.string.action_settings)) to
                        ::openDndSettings
                ))
            }
            addView(divider())
            addView(checkRow(
                R.drawable.ic_battery_full, !s.batteryOptimized, getString(R.string.check_battery),
                getString(if (s.batteryOptimized) R.string.check_battery_off else R.string.check_battery_ok),
                if (s.batteryOptimized) getString(R.string.action_fix) to ::requestBatteryExemption else null
            ))
        }, matchWrap())

        // The paired computers, each with its own key, and the way to add one.
        addView(text(getString(R.string.section_computers), Type.OVERLINE, Ui.FAINT), matchWrap(top = dp(28), bottom = dp(8)))
        addView(card().apply {
            val date = android.text.format.DateFormat.getMediumDateFormat(context)
            s.hosts.sortedBy { it.pairedAt }.forEachIndexed { i, h ->
                if (i > 0) addView(divider())
                val name = Ui.hostName(context, h.id, h.label)
                val broken = h.id in s.invalidated
                val detail = when {
                    broken -> getString(R.string.host_invalidated)
                    h.id == Hosts.LEGACY_ID -> getString(R.string.host_legacy_detail)
                    h.confirmed -> getString(R.string.host_trusted, date.format(h.pairedAt))
                    else -> getString(R.string.host_pending, date.format(h.pairedAt))
                }
                addView(checkRow(R.drawable.ic_computer, !broken && h.confirmed && h.id != Hosts.LEGACY_ID, name, detail,
                    getString(R.string.action_remove) to { confirmRemove(h) }))
            }
            addView(divider())
            addView(text(getString(R.string.computers_body), Type.BODY, Ui.MUTED))
            addView(button(getString(R.string.pair_start), Kind.PRIMARY, R.drawable.ic_computer) { startPairing() },
                matchWrap(top = dp(16)))
        }, matchWrap())

        addView(button(getString(R.string.reset_key), Kind.GHOST) { confirmReset() }, wrap(top = dp(20)))
    }

    // ---------------------------------------------------------------- pairing

    /** Set once this process has seen the phone make a key in secure hardware. */
    private var hardwareChecked = false

    /**
     * "Pair a computer": arm one pairing exchange, become discoverable, show the screen.
     *
     * The key itself is made when the computer asks (it is part of what the phone commits
     * to), so first make sure this phone CAN make one: a fingerprint enrolled, and a Keystore
     * that really puts keys in secure hardware. Otherwise the computer would only hear
     * "refused", with the reason visible nowhere.
     */
    private fun startPairing() {
        if (biometricStatus() != BiometricManager.BIOMETRIC_SUCCESS) { render(); return }
        if (!hardwareChecked) {
            val probe = "sudostamp-probe"
            try {
                Log.i(TAG, "a test key landed in ${Keys.create(probe, allowSoftware = AgentService.debuggable(this))}")
                hardwareChecked = true
            } catch (e: Exception) {
                Log.w(TAG, "cannot make keys", e)
                toast(getString(R.string.key_failed, e.message ?: e.javaClass.simpleName))
                return
            } finally {
                runCatching { Keys.delete(probe) }
            }
        }
        runCatching { startForegroundService(Intent(this, AgentService::class.java)) }
        AgentService.pairing.arm()
        startAdvertising()
        renderPairing()
    }

    private fun cancelPairing() {
        AgentService.pairing.disarm()
        AgentService.discardAbandoned(this)
        stopAdvertising()
        render()
    }

    /**
     * Advertise `_sudostamp._tcp` with NsdManager (platform API, no dependency) for as long as
     * pairing is armed. Discovery is only a convenience: the computer verifies whatever it
     * finds with the code, so a fake advertisement can waste a pairing, never win one.
     */
    private fun startAdvertising() {
        if (nsdListener != null) return
        val info = NsdServiceInfo().apply {
            serviceName = getString(R.string.nsd_name, Build.MODEL)
            serviceType = "_sudostamp._tcp"
            port = AgentService.PORT
        }
        val l = object : NsdManager.RegistrationListener {
            override fun onServiceRegistered(i: NsdServiceInfo) { Log.i(TAG, "discoverable as '${i.serviceName}'") }
            override fun onRegistrationFailed(i: NsdServiceInfo, code: Int) { Log.w(TAG, "discovery registration failed: $code") }
            override fun onServiceUnregistered(i: NsdServiceInfo) { Log.i(TAG, "no longer discoverable") }
            override fun onUnregistrationFailed(i: NsdServiceInfo, code: Int) = Unit
        }
        runCatching {
            getSystemService(NsdManager::class.java).registerService(info, NsdManager.PROTOCOL_DNS_SD, l)
            nsdListener = l
        }.onFailure { Log.w(TAG, "cannot advertise: ${it.message}") }
    }

    private fun stopAdvertising() {
        val l = nsdListener ?: return
        nsdListener = null
        runCatching { getSystemService(NsdManager::class.java).unregisterService(l) }
    }

    private fun renderPairing() {
        val v = AgentService.pairing.view()
        screen = Screen.PAIRING
        interceptBack(true)
        shownPairing = v
        tick.removeCallbacksAndMessages(null)
        // Discoverable only until a computer has asked: after that, an advertisement only tells
        // others on the network that a pairing is in progress.
        if (!AgentService.pairing.discoverable()) stopAdvertising()
        // The screen stays on while a pairing is open, so leaving it (onStop) is a deliberate
        // act that ends the pairing rather than the display timing out mid-code.
        if (AgentService.pairing.armed()) window.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        else window.clearFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        show(frame(centered = true) {
            when (v.state) {
                PairingSession.State.WAITING, PairingSession.State.COMMITTED -> {
                    addView(text(getString(R.string.pair_overline), Type.OVERLINE, Ui.ACCENT, center = true), matchWrap())
                    addView(mark(150, top = dp(12), bottom = dp(4)).apply {
                        countDown(v.deadline - Pairing.CODE_TTL_MS, Pairing.CODE_TTL_MS)
                    })
                    addView(text(getString(R.string.pair_title), Type.DISPLAY, center = true), matchWrap())
                    addView(text(getString(R.string.pair_run), Type.BODY, Ui.MUTED, center = true), matchWrap(top = dp(10)))
                    addView(card().apply {
                        addView(field(getString(R.string.pair_command_label), SETUP_COMMAND, mono = true).apply {
                            // The URL is long: smaller mono so it wraps in two or three lines.
                            (getChildAt(1) as TextView).setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 12f)
                        })
                        addView(text(getString(R.string.pair_arch), Type.CAPTION, Ui.MUTED), matchWrap(top = dp(8)))
                        addView(button(getString(R.string.copy_command), Kind.SECONDARY, R.drawable.ic_terminal) {
                            copy(SETUP_COMMAND, getString(R.string.copied_command))
                        }, matchWrap(top = dp(12)))
                        addView(divider())
                        addView(field(getString(R.string.field_address), address(), mono = true))
                        addView(text(getString(R.string.pair_address_hint), Type.CAPTION, Ui.MUTED), matchWrap(top = dp(6)))
                    }, matchWrap(top = dp(20)))
                    addView(button(getString(R.string.cancel), Kind.GHOST) { cancelPairing() }, wrap(top = dp(12)))
                }
                PairingSession.State.CODE -> {
                    addView(text(getString(R.string.pair_overline), Type.OVERLINE, Ui.ACCENT, center = true), matchWrap())
                    addView(text(getString(R.string.pair_code_title, v.label ?: ""), Type.TITLE, center = true),
                        matchWrap(top = dp(16)))
                    addView(text(Pairing.spaced(v.code ?: "------"), Type.CODE, Ui.FG, center = true).apply {
                        setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 52f)
                        letterSpacing = 0.08f
                        contentDescription = (v.code ?: "").toCharArray().joinToString(" ")
                    }, matchWrap(top = dp(24), bottom = dp(8)))
                    addView(text(getString(R.string.pair_code_from, v.client ?: ""), Type.CAPTION, Ui.MUTED, center = true),
                        matchWrap())
                    addView(text(getString(R.string.pair_code_hint), Type.CAPTION, Ui.FAINT, center = true),
                        matchWrap(top = dp(20)))
                    addView(button(getString(R.string.cancel), Kind.GHOST) { cancelPairing() }, wrap(top = dp(16)))
                }
                PairingSession.State.DONE -> {
                    addView(ResultMark(context, Ui.ACCENT, true, getString(R.string.pair_done)).apply {
                        layoutParams = LinearLayout.LayoutParams(dp(120), dp(120)).apply { gravity = Gravity.CENTER_HORIZONTAL }
                    })
                    addView(text(getString(R.string.pair_done), Type.DISPLAY, Ui.ACCENT, center = true), matchWrap(top = dp(20)))
                    addView(text(getString(R.string.pair_done_detail, v.label ?: ""), Type.BODY, Ui.MUTED, center = true),
                        matchWrap(top = dp(8)))
                    addView(button(getString(R.string.pair_finish), Kind.SECONDARY) { cancelPairing() }, matchWrap(top = dp(28)))
                }
                PairingSession.State.INTERRUPTED -> {
                    addView(ResultMark(context, Ui.DANGER, false, getString(R.string.pair_interrupted)).apply {
                        layoutParams = LinearLayout.LayoutParams(dp(120), dp(120)).apply { gravity = Gravity.CENTER_HORIZONTAL }
                    })
                    addView(text(getString(R.string.pair_interrupted), Type.DISPLAY, Ui.DANGER, center = true), matchWrap(top = dp(20)))
                    addView(text(getString(R.string.pair_interrupted_detail), Type.BODY, Ui.MUTED, center = true),
                        matchWrap(top = dp(8)))
                    addView(button(getString(R.string.pair_again), Kind.PRIMARY) { startPairing() }, matchWrap(top = dp(28)))
                    addView(button(getString(R.string.cancel), Kind.GHOST) { cancelPairing() }, wrap(top = dp(8)))
                }
                else -> {   // EXPIRED, IDLE
                    addView(text(getString(R.string.pair_expired), Type.DISPLAY, center = true), matchWrap())
                    addView(text(getString(R.string.pair_expired_detail), Type.BODY, Ui.MUTED, center = true),
                        matchWrap(top = dp(8)))
                    addView(button(getString(R.string.pair_again), Kind.PRIMARY) { startPairing() }, matchWrap(top = dp(28)))
                    addView(button(getString(R.string.cancel), Kind.GHOST) { cancelPairing() }, wrap(top = dp(8)))
                }
            }
            entrance()
        })
        // Expiry has no event of its own: look again every second while pairing is live.
        if (AgentService.pairing.armed()) {
            tick.postDelayed(object : Runnable {
                override fun run() {
                    if (screen != Screen.PAIRING) return
                    sync()
                    if (screen == Screen.PAIRING && AgentService.pairing.armed()) tick.postDelayed(this, 1000)
                }
            }, 1000)
        }
    }

    // ---------------------------------------------------------------- approval

    /** The approval moment: a request is parked in the service. Shows WHO is asking and
     *  WHEN behind the system's biometric sheet, which is raised immediately so a
     *  notification tap goes straight to the fingerprint. Deny is always one tap away. */
    private fun renderApproval(p: Approval) {
        screen = Screen.APPROVAL
        shownRequest = p.id
        interceptBack(false)
        tick.removeCallbacksAndMessages(null)
        val name = Ui.hostName(this, p.hostId, p.label)
        val left = text("", Type.CODE_SMALL, Ui.MUTED, center = true)

        show(frame(centered = true) {
            addView(text(getString(R.string.approval_overline), Type.OVERLINE, Ui.ACCENT, center = true), matchWrap())
            addView(mark(200, top = dp(16), bottom = dp(8)).apply {
                countDown(p.arrivedAt, AgentService.APPROVAL_TIMEOUT_MS)
            })
            addView(text(getString(R.string.approval_title, name), Type.DISPLAY, center = true), matchWrap())
            addView(left, matchWrap(top = dp(6)))

            addView(card().apply {
                addView(field(getString(R.string.approval_from), p.client, mono = true))
                addView(text(
                    getString(R.string.approval_received,
                        android.text.format.DateFormat.getTimeFormat(context).format(p.arrivedAt)),
                    Type.CAPTION, Ui.MUTED
                ), matchWrap(top = dp(4)))
                // Approving a request you did not start is the one way this goes wrong. A computer
                // never approved before, or the old shared key, is worth a second look.
                val warning = when {
                    p.hostId == Hosts.LEGACY_ID -> R.string.approval_legacy
                    !p.trusted -> R.string.approval_new_host
                    else -> null
                }
                if (warning != null) {
                    addView(row().apply {
                        gravity = Gravity.TOP
                        background = Ui.rounded(Ui.WARN_DIM, dpf(12f))
                        setPadding(dp(12), dp(10), dp(12), dp(10))
                        addView(icon(R.drawable.ic_warning, Ui.WARN, 18))
                        addView(text(getString(warning), Type.CAPTION, Ui.WARN).apply {
                            setPadding(dp(10), 0, 0, 0)
                        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                    }, matchWrap(top = dp(14)))
                }
            }, matchWrap(top = dp(24)))

            addView(button(getString(R.string.approval_approve), Kind.PRIMARY, R.drawable.ic_lock) {
                if (promptFor == null && !p.isResolved && resumed) prompt(p)
            }, matchWrap(top = dp(20)))
            addView(button(getString(R.string.deny), Kind.DANGER) { deny(p) }, matchWrap(top = dp(12)))
            entrance()
        })

        // "N s left", once a second, for as long as this request is the one on screen.
        val update = object : Runnable {
            override fun run() {
                if (screen != Screen.APPROVAL || p.isResolved) return
                val ms = p.arrivedAt + AgentService.APPROVAL_TIMEOUT_MS - System.currentTimeMillis()
                left.text = getString(R.string.approval_left, (ms / 1000).coerceAtLeast(0))
                left.setTextColor(if (ms < AgentService.APPROVAL_TIMEOUT_MS / 4) Ui.WARN else Ui.MUTED)
                tick.postDelayed(this, ms.mod(1000L) + 10)
            }
        }
        update.run()
    }

    // ------------------------------------------------------------------ result

    private enum class Outcome { APPROVED, DENIED, EXPIRED }

    /**
     * A brief full-screen result. APPROVED then closes the app; a refusal goes back to setup.
     *
     * There is nothing left to show once the TEE has signed: the signature is already on
     * its way to the host, and the listener lives in the foreground service, not in this
     * screen. Leaving the setup screen up would park the phone on a screen the user never
     * asked for after every sudo, so we get out of the way -- the result is all the feedback
     * an approval needs.
     *
     * Deferred, not instant: a window that vanishes the moment the sensor reports a match
     * reads as a crash. And a request that arrives during the flash wins -- sync()
     * cancels this close and puts the approval screen back up.
     */
    private fun renderResult(outcome: Outcome, name: String) {
        screen = Screen.RESULT
        tick.removeCallbacksAndMessages(null)
        val (color, title, detail) = when (outcome) {
            Outcome.APPROVED -> Triple(Ui.ACCENT, getString(R.string.result_approved),
                getString(R.string.result_approved_detail, name))
            Outcome.DENIED -> Triple(Ui.DANGER, getString(R.string.result_denied),
                getString(R.string.result_denied_detail))
            Outcome.EXPIRED -> Triple(Ui.WARN, getString(R.string.result_expired),
                getString(R.string.result_expired_detail))
        }
        show(frame(centered = true) {
            addView(ResultMark(context, color, outcome == Outcome.APPROVED, title).apply {
                layoutParams = LinearLayout.LayoutParams(dp(132), dp(132)).apply {
                    gravity = Gravity.CENTER_HORIZONTAL
                }
            })
            addView(text(title, Type.DISPLAY, color, center = true), matchWrap(top = dp(24)))
            addView(text(detail, Type.BODY, Ui.MUTED, center = true), matchWrap(top = dp(8)))
        })
        window.decorView.performHapticFeedback(
            if (outcome == Outcome.APPROVED) HapticFeedbackConstants.CONFIRM else HapticFeedbackConstants.REJECT
        )
        if (outcome == Outcome.APPROVED) {
            ui.postDelayed({
                // Nothing pending => this approval is genuinely over, so close. (The check is
                // belt-and-braces: a new request also cancels this callback outright.)
                if (AgentService.currentRequest()?.isResolved != false) finishAfterApproval()
            }, APPROVAL_FLASH_MS)
        } else {
            ui.postDelayed({ if (screen == Screen.RESULT) render() }, REFUSAL_FLASH_MS)
        }
    }

    /**
     * The approval is done, so the app is done. finishAndRemoveTask() closes the activity
     * AND drops the task from recents: an approval screen has no business being reopened
     * later, and the listener is unaffected -- it lives in the foreground service.
     */
    private fun finishAfterApproval() {
        Log.i(TAG, "approved: closing the app")
        finishAndRemoveTask()
    }

    // ------------------------------------------------------------------ actions

    /** Asks for the notification permission; once refused for good, the system will not
     *  show the dialog again, so the app's notification settings are opened instead. */
    private fun requestNotifications() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val perm = Manifest.permission.POST_NOTIFICATIONS
        if (!askedNotifications || shouldShowRequestPermissionRationale(perm)) {
            askedNotifications = true
            requestPermissions(arrayOf(perm), REQ_NOTIFICATIONS)
        } else {
            runCatching {
                startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                    .putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
            }
        }
    }

    /** Copies [value] (a public key or a command: not secret). Android 13+ shows its own
     *  confirmation, so a toast there would say it twice. */
    private fun copy(value: String, confirmation: String) {
        val clip = ClipData.newPlainText(getString(R.string.app_name), value)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, false)
            }
        }
        (getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(clip)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) toast(confirmation)
    }

    /** Ask the system to exempt us from battery optimization. Tries the direct dialog
     *  first, then falls back to the settings list on OEM builds that reject it. */
    private fun requestBatteryExemption() {
        try {
            Log.i(TAG, "requesting battery-optimization exemption for $packageName")
            startActivity(
                Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                    .setData(Uri.parse("package:$packageName"))
            )
        } catch (e: Exception) {
            Log.w(TAG, "direct exemption intent failed: ${e.message}; opening settings list")
            try {
                startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
            } catch (e2: Exception) {
                Log.e(TAG, "battery settings intent failed too: ${e2.message}")
                toast(getString(R.string.battery_manual))
            }
        }
    }

    private fun confirmReset() {
        AlertDialog.Builder(this)
            .setTitle(R.string.reset_title)
            .setMessage(R.string.reset_message)
            .setPositiveButton(R.string.reset_confirm) { _, _ ->
                Hosts.all(this).forEach { AgentService.forget(this, it.id) }
                stopService(Intent(this, AgentService::class.java))
                render()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun confirmRemove(h: Host) {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.remove_title, Ui.hostName(this, h.id, h.label)))
            .setMessage(R.string.remove_message)
            .setPositiveButton(R.string.remove_confirm) { _, _ ->
                AgentService.forget(this, h.id)
                if (Hosts.all(this).isEmpty()) stopService(Intent(this, AgentService::class.java))
                render()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    // --------------------------------------------------------------- biometric

    /** Reject the parked request without touching the sensor. The service answers
     *  SSH_AGENT_FAILURE; the prompt is taken down and the result shown. */
    private fun deny(p: Approval) {
        val first = p.deny()
        closePrompt()?.cancel()
        if (first) renderResult(Outcome.DENIED, p.label) else sync()
    }

    /** Forgets the open prompt and returns its cancel handle. Its callbacks see that they
     *  are no longer current and stay out of the UI. */
    private fun closePrompt(): CancellationSignal? {
        val c = promptCancel
        promptFor = null
        promptCancel = null
        return c
    }

    private fun prompt(p: Approval) {
        val cancel = CancellationSignal()
        promptFor = p
        promptCancel = cancel
        /** True if this prompt is still the open one; a superseded prompt only denies. */
        fun current() = promptCancel === cancel

        try {
            BiometricPrompt.Builder(this)
                // The computer's name in the title, where it cannot be missed: the system sheet
                // covers the app's own screen.
                .setTitle(getString(R.string.prompt_title, Ui.hostName(this, p.hostId, p.label)))
                .setSubtitle(getString(R.string.prompt_subtitle, p.client))
                .setDescription(getString(R.string.prompt_description))
                // Stated, not left to the default: with a passive biometric (Class 3 face
                // unlock) a mere glance at the screen must never approve a sudo.
                .setConfirmationRequired(true)
                .setNegativeButton(getString(R.string.deny), mainExecutor) { _, _ ->
                    val first = p.deny()               // => SSH_AGENT_FAILURE
                    if (current()) {
                        closePrompt()
                        if (first) renderResult(Outcome.DENIED, p.label) else sync()
                    }
                }
                .build()
                .authenticate(
                    BiometricPrompt.CryptoObject(p.signer),
                    cancel,
                    mainExecutor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(
                            result: BiometricPrompt.AuthenticationResult
                        ) {
                            val delivered = try {
                                // The TEE authorised THIS Signature object. Calling sign()
                                // before this point throws -- that is the hard gate.
                                p.signer.update(p.data)
                                p.approve(p.signer.sign())
                            } catch (e: Exception) {
                                Log.w(TAG, "signing failed: ${e.message}")
                                p.deny()
                                false
                            }
                            if (!current()) return
                            closePrompt()
                            // Signed too late, the agent had already answered FAILURE:
                            // claiming success here would be a lie about sudo.
                            renderResult(if (delivered) Outcome.APPROVED else Outcome.EXPIRED,
                                Ui.hostName(this@MainActivity, p.hostId, p.label))
                        }

                        override fun onAuthenticationError(code: Int, msg: CharSequence?) {
                            val first = p.deny()
                            if (!current()) return
                            closePrompt()
                            // Back, or a tap outside the sheet, is the user saying no; say
                            // so. Anything else (lockout, hardware) goes back to setup.
                            if (first && code == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED) {
                                renderResult(Outcome.DENIED, p.label)
                            } else {
                                sync()
                            }
                        }

                        override fun onAuthenticationFailed() {
                            // A single bad match. The prompt stays open to retry, so do NOT
                            // resolve the request -- an eventual success must still win.
                        }
                    }
                )
        } catch (e: Exception) {
            // e.g. no biometrics enrolled, or the prompt cannot be raised in this state.
            // Fail closed: deny so the agent answers FAILURE now instead of stalling the
            // connection for the whole approval window.
            Log.w(TAG, "cannot show biometric prompt: ${e.message}")
            p.deny()
            closePrompt()
            sync()
        }
    }

    private fun toast(m: String) = Toast.makeText(this, m, Toast.LENGTH_SHORT).show()
}
