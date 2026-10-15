package com.ritwick.sudostamp

import java.security.SecureRandom

/**
 * The phone's side of one pairing (see [Pairing] for the protocol and why it is shaped so).
 *
 * ONE ATTEMPT PER ARMING. The user taps "Pair a computer"; that allows exactly one
 * commit -> reveal exchange. Without this rule the 6-digit code could be ground down: someone
 * in the middle, who can compute the code the COMPUTER will expect, could quietly repeat
 * pairing with the phone, each time with a fresh phone nonce, until the phone happened to show
 * that same code -- about a million cheap round trips. With one exchange per tap, each attempt
 * costs a deliberate user action, and a second commit while a pairing is in progress is itself
 * a red flag: it aborts the pairing and says so on screen.
 *
 * All methods are synchronized: the listener thread drives the protocol, the UI reads [view].
 */
class PairingSession(
    private val now: () -> Long = System::currentTimeMillis,
    private val random: (Int) -> ByteArray = { n -> ByteArray(n).also { SecureRandom().nextBytes(it) } },
) {
    enum class State { IDLE, WAITING, COMMITTED, CODE, DONE, INTERRUPTED, EXPIRED }

    /** What the screen shows. [code] only in CODE; [label]/[client] once a computer asked. */
    data class View(val state: State, val label: String?, val client: String?, val code: String?, val deadline: Long)

    private var state = State.IDLE
    private var deadline = 0L
    private var label: String? = null
    private var client: String? = null
    private var conn = -1L
    private var keyBlob: ByteArray? = null
    private var phoneNonce: ByteArray? = null
    private var hostNonce: ByteArray? = null
    private var code: String? = null

    /** The user asked to pair: allow one exchange for [Pairing.CODE_TTL_MS]. */
    @Synchronized
    fun arm() {
        clear()
        state = State.WAITING
        deadline = now() + Pairing.CODE_TTL_MS
    }

    /** The user left the pairing screen or cancelled. */
    @Synchronized
    fun disarm() {
        clear()
        state = State.IDLE
    }

    @Synchronized
    fun view(): View {
        expire()
        return View(state, label, client, code, deadline)
    }

    /** True while the phone should be discoverable and accept a pairing. */
    @Synchronized
    fun armed(): Boolean {
        expire()
        return state == State.WAITING || state == State.COMMITTED || state == State.CODE
    }

    /**
     * pair-commit from [fromClient] on connection [connId]. Returns the commitment, or null to
     * refuse. A commit while another pairing is under way interrupts it: two computers pairing
     * at once is either a mistake or someone trying their luck, and both deserve a visible stop.
     */
    @Synchronized
    fun commit(fromClient: String, connId: Long, rawLabel: ByteArray, ourKey: ByteArray): ByteArray? {
        expire()
        when (state) {
            State.WAITING -> Unit
            State.COMMITTED, State.CODE -> { interrupt(); return null }
            else -> return null
        }
        val np = random(Pairing.NONCE_BYTES)
        state = State.COMMITTED
        label = Pairing.cleanLabel(rawLabel)
        client = fromClient
        conn = connId
        keyBlob = ourKey.copyOf()
        phoneNonce = np
        return Pairing.commitment(ourKey, np)
    }

    /**
     * pair-reveal: the computer's nonce, on the SAME connection as its commit. Returns the key
     * and the phone nonce, and from then on the screen shows the code. Anything else refuses;
     * a reveal for this pairing from somewhere else interrupts it.
     */
    @Synchronized
    fun reveal(fromClient: String, connId: Long, nh: ByteArray): Pair<ByteArray, ByteArray>? {
        expire()
        if (state != State.COMMITTED) return null
        if (fromClient != client || connId != conn) { interrupt(); return null }
        if (nh.size != Pairing.NONCE_BYTES) return null
        val k = keyBlob!!
        val np = phoneNonce!!
        hostNonce = nh.copyOf()
        code = Pairing.code(k, np, nh)
        state = State.CODE
        return k.copyOf() to np.copyOf()
    }

    /**
     * pair-done: the computer accepted the typed code. Display only -- nothing on the phone
     * depends on it -- but it must name THIS pairing (same host, same nonce) to count.
     */
    @Synchronized
    fun done(fromClient: String, nh: ByteArray): Boolean {
        expire()
        if (state != State.CODE || fromClient != client || !nh.contentEquals(hostNonce)) return false
        state = State.DONE
        return true
    }

    private fun interrupt() {
        clear()
        state = State.INTERRUPTED
    }

    private fun expire() {
        if ((state == State.WAITING || state == State.COMMITTED || state == State.CODE) && now() >= deadline) {
            clear()
            state = State.EXPIRED
        }
    }

    private fun clear() {
        label = null; client = null; conn = -1; keyBlob = null
        phoneNonce = null; hostNonce = null; code = null
    }
}
