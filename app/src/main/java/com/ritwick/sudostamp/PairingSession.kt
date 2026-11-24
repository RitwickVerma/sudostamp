package com.ritwick.sudostamp

import java.security.SecureRandom

/**
 * The phone's side of one pairing (see [Pairing] for the protocol and why it is shaped so).
 *
 * ONE ATTEMPT PER ARMING. The user taps "Pair a computer"; that allows exactly one
 * commit -> reveal -> done exchange. Without this rule the 6-digit code could be ground down:
 * someone in the middle could repeat pairing with the phone, each time with a fresh phone
 * nonce, until the phone happened to show the code the computer expects. With one exchange
 * per tap, each attempt costs a deliberate user action.
 *
 * A SECOND COMPUTER CANCELS. Any commit after the first, from anywhere, while the arming lasts
 * -- even after a pairing finished -- stops it and throws its key away. pair-done proves
 * nothing about the person (whoever ran commit and reveal knows its own nonce), so an attacker
 * on the network can race the person's computer and finish first. The person's own computer
 * then arrives second, which cancels the attacker's pairing and says so on screen. And a key
 * that did get through still starts out PENDING: it is trusted only once a request from its
 * computer has been approved (see [Hosts]).
 *
 * THE PERSON CONFIRMS (code mode). pair-done comes over the LAN, so a party in the middle can
 * send it for a pairing it altered (its own host key H in the reveal): the person's computer then
 * says the code does not match and pins nothing, but the phone would have kept the altered entry
 * under that computer's name. So after pair-done the phone asks the person whether the computer
 * said it paired ([State.CONFIRM]), and records the computer only on [confirm]. No, leaving the
 * screen, the time running out or a second computer throw the key away. QR mode needs no such
 * step: its pair-done proves the scanned secret.
 *
 * Side effects (making and deleting Keystore keys, recording the computer) stay with the
 * caller: [commit] takes a key factory, [done] returning true is the caller's cue to record the
 * computer, and every key this session gave up on -- including a finished pairing that a
 * second computer then cancelled -- is handed back by [drainDiscarded] for deletion.
 *
 * BY QR CODE (see [Pairing], qr-v1): [armQr] instead of [arm]. The two modes never mix: in
 * one, every message of the other is refused without effect. In QR mode a message that does not
 * prove the secret is refused WITHOUT effect too -- not an interruption, as a stray code-mode
 * commit is -- because there it proves nothing; a second message that does prove it still stops
 * the pairing, as in code mode.
 *
 * All methods are synchronized: the listener thread drives the protocol, the UI reads [view].
 */
class PairingSession(
    private val now: () -> Long = System::currentTimeMillis,
    private val random: (Int) -> ByteArray = { n -> ByteArray(n).also { SecureRandom().nextBytes(it) } },
) {
    /** OUTDATED: a computer tried the pairing protocol of SudoStamp 1.3 or older, which this
     *  app refuses; the screen tells the person to update the computer's installer. */
    enum class State { IDLE, WAITING, COMMITTED, CODE, CONFIRM, DONE, INTERRUPTED, EXPIRED, OUTDATED }

    /** A code-mode pairing the person confirmed: what the caller records (see [Hosts]). */
    class Confirmed(val id: String, val label: String?, val client: String, val hostKey: ByteArray?)

    /** What the screen shows. [code] only in CODE; [label]/[client] once a computer asked. */
    data class View(
        val state: State, val label: String?, val client: String?, val code: String?, val deadline: Long,
        val qr: Boolean = false,
    )

    /** The Keystore's attestation of a new key: the challenge it was made with, and the
     *  certificate chain (DER, leaf first). Held in memory for the one pairing, never stored. */
    class Attestation(val challenge: ByteArray, val chain: List<ByteArray>)

    /** A key made for this pairing: its id (see [Hosts]), SSH public key blob and, where the
     *  Keystore could give one, its attestation. */
    data class NewKey(val id: String, val blob: ByteArray, val attestation: Attestation? = null)

    private var state = State.IDLE
    private var deadline = 0L
    private var label: String? = null
    private var client: String? = null
    private var conn = -1L
    private var key: NewKey? = null
    private var dialled: ByteArray? = null
    private var stable: ByteArray? = null
    private var phoneNonce: ByteArray? = null
    private var hostNonce: ByteArray? = null
    private var code: String? = null
    /** Pairing v3: the computer's host key H (a P-256 point), or null for a v2 computer. */
    private var hostKey: ByteArray? = null
    /** Set in QR mode only: the secret the scanned code carried. */
    private var qr: ByteArray? = null
    /** QR mode: the nonce each connection's hello was answered with (Nc), spent by its commit.
     *  A handful at most: the computer probes now and then; the oldest go first. */
    private val helloNonces = object : LinkedHashMap<Long, ByteArray>() {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, ByteArray>?) = size > 8
    }
    private val discarded = ArrayList<String>()

    /** The user asked to pair: allow one exchange for [Pairing.CODE_TTL_MS]. */
    @Synchronized
    fun arm() {
        abandon()
        state = State.WAITING
        deadline = now() + Pairing.CODE_TTL_MS
    }

    /** The user confirmed a scanned code: allow one QR exchange for [Pairing.CODE_TTL_MS] with
     *  the computer that holds [secret], named [computer] (from the code; display text). */
    @Synchronized
    fun armQr(secret: ByteArray, computer: String) {
        require(secret.size == Pairing.QR_SECRET_BYTES)
        abandon()
        state = State.WAITING
        deadline = now() + Pairing.CODE_TTL_MS
        qr = secret.copyOf()
        label = computer
    }

    /** The user left the pairing screen or cancelled. A finished pairing is kept. */
    @Synchronized
    fun disarm() {
        abandon()
        state = State.IDLE
    }

    @Synchronized
    fun view(): View {
        expire()
        return View(state, label, client, code, deadline, qr != null)
    }

    /** True while the phone should be discoverable: only until a computer has committed. */
    @Synchronized
    fun discoverable(): Boolean {
        expire()
        return state == State.WAITING
    }

    /** True while a pairing can still progress (or be cancelled by a second computer). */
    @Synchronized
    fun armed(): Boolean {
        expire()
        return state == State.WAITING || state == State.COMMITTED || state == State.CODE ||
            state == State.CONFIRM || (state == State.DONE && now() < deadline)
    }

    /** Ids of keys made by this session and then given up on; the caller deletes them. */
    @Synchronized
    fun drainDiscarded(): List<String> {
        expire()
        return discarded.toList().also { discarded.clear() }
    }

    /**
     * pair-commit from [fromClient] on connection [connId], dialled at [dialledAt] (see
     * [Pairing.ENDPOINT_BYTES]); [stableAt] is the address the computer should keep.
     * [makeKey] creates the key for this computer, given the attestation challenge of this
     * pairing (see [Pairing.attestChallenge]). Returns the commitment, or null to refuse.
     */
    @Synchronized
    fun commit(
        fromClient: String, connId: Long, rawLabel: ByteArray,
        dialledAt: ByteArray, stableAt: ByteArray, makeKey: (challenge: ByteArray) -> NewKey?,
    ): ByteArray? {
        expire()
        if (qr != null) return null
        when (state) {
            State.WAITING -> Unit
            State.COMMITTED, State.CODE, State.CONFIRM -> { interrupt(); return null }
            State.DONE -> { if (now() < deadline) interrupt(); return null }
            else -> return null
        }
        if (dialledAt.size != Pairing.ENDPOINT_BYTES || stableAt.size != Pairing.ENDPOINT_BYTES) return null
        // Np first: the attestation challenge is made from it, and the key must carry the challenge.
        val np = random(Pairing.NONCE_BYTES)
        val k = makeKey(Pairing.attestChallenge(np, dialledAt, stableAt)) ?: return null
        state = State.COMMITTED
        label = Pairing.cleanLabel(rawLabel)
        client = fromClient
        conn = connId
        key = k
        dialled = dialledAt.copyOf()
        stable = stableAt.copyOf()
        phoneNonce = np
        return Pairing.commitment(k.blob, np, dialledAt, stableAt)
    }

    /** What the phone reveals: its key for this computer, its nonce, and the two endpoints. */
    class Reveal(val keyBlob: ByteArray, val phoneNonce: ByteArray, val dialled: ByteArray, val stable: ByteArray)

    /**
     * pair-reveal: the computer's nonce, on the SAME connection as its commit, and (v3) its host
     * key [h], which the code then covers. From then on the screen shows the code. Anything else
     * refuses; a reveal from somewhere else interrupts.
     */
    @Synchronized
    fun reveal(fromClient: String, connId: Long, nh: ByteArray, h: ByteArray? = null): Reveal? {
        expire()
        if (state != State.COMMITTED || qr != null) return null
        if (fromClient != client || connId != conn) { interrupt(); return null }
        if (nh.size != Pairing.NONCE_BYTES) return null
        // A host key that is not a P-256 point stops the pairing: see AgentService for why it is
        // not refused quietly (the computer would retry without one).
        if (h != null && !validHostKey(h)) { interrupt(); return null }
        val k = key!!
        val np = phoneNonce!!
        hostNonce = nh.copyOf()
        hostKey = h?.copyOf()
        code = Pairing.code(k.blob, np, nh, dialled!!, stable!!, h)
        state = State.CODE
        return Reveal(k.blob.copyOf(), np.copyOf(), dialled!!.copyOf(), stable!!.copyOf())
    }

    /**
     * pair-done: the computer says the typed code matched. It must name THIS pairing (same
     * host, same nonce) to count, but it proves nothing (see the class comment): the pairing
     * now waits for the person's [confirm], with a fresh [Pairing.CODE_TTL_MS] to give it.
     * Returns the key's id on success, so the computer can go on to ask for the attestation.
     */
    @Synchronized
    fun done(fromClient: String, nh: ByteArray): String? {
        expire()
        if (qr != null || state != State.CODE || fromClient != client || !nh.contentEquals(hostNonce)) return null
        state = State.CONFIRM
        deadline = now() + Pairing.CODE_TTL_MS
        return key!!.id
    }

    /** The person says the computer reported the pairing: it is finished, and the caller records
     *  what this returns. Null unless a pairing is waiting for exactly that, in time. */
    @Synchronized
    fun confirm(): Confirmed? {
        expire()
        if (state != State.CONFIRM) return null
        val from = client ?: return null
        state = State.DONE
        return Confirmed(key!!.id, label, from, hostKey?.copyOf())
    }

    /** The person says the computer did NOT report the pairing: stop it, throw its key away. */
    @Synchronized
    fun reject() {
        expire()
        if (state == State.CONFIRM) interrupt()
    }

    /** The host key of the pairing that just finished (v3), or null: read by the caller right
     *  after [done] / [qrDone] succeeded, to record it with the computer. */
    @Synchronized
    fun doneHostKey(): ByteArray? = if (state == State.DONE) hostKey?.copyOf() else null

    /**
     * attest-v1: the attestation of the key THIS session made, or null. Served only to the
     * computer that paired, only after pair-done and only while the arming lasts; once the
     * screen closes, another computer cancels the pairing or the time is up, the key is gone
     * from the session and so is this. Never another key's chain, so nothing leaks about them.
     */
    @Synchronized
    fun attestation(fromClient: String): Attestation? {
        expire()
        if ((state != State.DONE && state != State.CONFIRM) || now() >= deadline || fromClient != client) return null
        return key?.attestation
    }

    /** What the phone answers a hello with: its nonce for this connection, and the proof. */
    class QrHelloReply(val connNonce: ByteArray, val mac: ByteArray)

    /** pair-qr-hello on [connId]: answered only in QR mode, to the computer whose secret hashes to
     *  [tag], with a fresh nonce for this connection (the one its commit must carry) and proof of
     *  the secret over the computer's nonce [nq]. Changes nothing else. Answered while the arming
     *  lasts, not only while waiting: a second holder of the secret must still be able to commit,
     *  which stops the pairing (see [qrCommit]). */
    @Synchronized
    fun qrHello(connId: Long, tag: ByteArray, nq: ByteArray): QrHelloReply? {
        expire()
        val s = qr ?: return null
        val open = state == State.WAITING || state == State.COMMITTED || (state == State.DONE && now() < deadline)
        if (!open || nq.size != Pairing.NONCE_BYTES || !Pairing.same(tag, Pairing.qrHello(s))) return null
        val nc = random(Pairing.NONCE_BYTES)
        helloNonces[connId] = nc
        return QrHelloReply(nc.copyOf(), Pairing.qrHelloReplyMac(s, nq, nc))
    }

    /** What the phone answers a valid pair-qr commit with. */
    class QrReply(val keyBlob: ByteArray, val phoneNonce: ByteArray, val dialled: ByteArray, val stable: ByteArray, val mac: ByteArray)

    /**
     * pair-qr from [fromClient] on [connId], after a hello on the same connection: the computer's
     * nonce and its proof of the secret over this connection's nonce and where it dialled, checked
     * against [dialledAt] (where this phone was dialled). Returns the reply, or null to refuse.
     * Refusing a message that does not prove the secret changes nothing: a commit replayed on
     * another connection finds no nonce of its own, or another one, and is refused like a forgery.
     */
    @Synchronized
    fun qrCommit(
        fromClient: String, connId: Long, nh: ByteArray, mac: ByteArray,
        dialledAt: ByteArray, stableAt: ByteArray, makeKey: (challenge: ByteArray) -> NewKey?,
        h: ByteArray? = null,
    ): QrReply? {
        expire()
        val s = qr ?: return null
        val nc = helloNonces.remove(connId) ?: return null
        if (nh.size != Pairing.NONCE_BYTES || dialledAt.size != Pairing.ENDPOINT_BYTES ||
            stableAt.size != Pairing.ENDPOINT_BYTES || (h != null && !validHostKey(h))) return null
        val expected = if (h == null) Pairing.qrCommitMac(s, nh, nc, dialledAt) else Pairing.qrCommitMacV3(s, nh, nc, dialledAt, h)
        if (!Pairing.same(mac, expected)) return null
        when (state) {
            State.WAITING -> Unit
            State.COMMITTED -> { interrupt(); return null }
            State.DONE -> { if (now() < deadline) interrupt(); return null }
            else -> return null
        }
        val np = random(Pairing.NONCE_BYTES)
        val k = makeKey(Pairing.attestChallenge(np, dialledAt, stableAt)) ?: return null
        state = State.COMMITTED
        client = fromClient
        conn = connId
        key = k
        dialled = dialledAt.copyOf()
        stable = stableAt.copyOf()
        phoneNonce = np
        hostNonce = nh.copyOf()
        hostKey = h?.copyOf()
        return QrReply(k.blob.copyOf(), np.copyOf(), dialledAt.copyOf(), stableAt.copyOf(),
            Pairing.qrPhoneMac(s, nh, nc, k.blob, np, dialledAt, stableAt))
    }

    /** pair-qr-done: on the commit's own connection, proving the secret over the key. Returns the
     *  key's id on success; anything else is refused without effect. */
    @Synchronized
    fun qrDone(fromClient: String, connId: Long, nh: ByteArray, mac: ByteArray): String? {
        expire()
        val s = qr ?: return null
        val k = key ?: return null
        if (state != State.COMMITTED || fromClient != client || connId != conn || !Pairing.same(nh, hostNonce)) return null
        if (!Pairing.same(mac, Pairing.qrDoneMac(s, nh, k.blob))) return null
        state = State.DONE
        return k.id
    }

    /** Throws away an unfinished pairing's key. A finished one stays with the caller. */
    private fun abandon() {
        if (state == State.COMMITTED || state == State.CODE || state == State.CONFIRM) key?.let { discarded += it.id }
        clear()
    }

    /**
     * A computer sent a pairing message of an older protocol (version 1). It is refused, as
     * before; but while the person is waiting on the pairing screen, say why, instead of leaving
     * them with "the phone refused" on the computer -- which is what happened when the AUR
     * package lagged a release behind the app. Only from WAITING, and it ends the arming.
     */
    @Synchronized
    fun olderProtocol(fromClient: String) {
        expire()
        if (state != State.WAITING || qr != null) return
        clear()
        client = fromClient
        state = State.OUTDATED
    }

    /** Stops the pairing, finished or not, and throws its key away. */
    private fun interrupt() {
        key?.let { discarded += it.id }
        clear()
        state = State.INTERRUPTED
    }

    private fun expire() {
        if ((state == State.WAITING || state == State.COMMITTED || state == State.CODE || state == State.CONFIRM) &&
            now() >= deadline) {
            abandon()
            state = State.EXPIRED
        }
    }

    private fun clear() {
        label = null; client = null; conn = -1; key = null; dialled = null; stable = null
        phoneNonce = null; hostNonce = null; code = null; qr = null; hostKey = null; helloNonces.clear()
    }

    private fun validHostKey(h: ByteArray) = runCatching { Hpke.publicKey(h) }.isSuccess
}
