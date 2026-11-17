package com.ritwick.sudostamp

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Pairing: how a computer learns the key this phone made FOR IT, and the address to reach it
 * at, without trusting the network.
 *
 * The danger it answers: anything that can answer at the phone's address during setup (an
 * impostor, or a man in the middle) could hand the computer ITS key instead, and the computer
 * would pin it. A short code is easy to compare but, naively, easy to forge: an impostor could
 * generate keys until one gives the same 6 digits. So this is numeric comparison with a
 * COMMITMENT (as in Bluetooth Secure Simple Pairing, ZRTP, Vaudenay's SAS-MCA):
 *
 *   computer -> phone     pair-commit-v2(label)
 *   phone                 makes a NEW key K for this computer; Np: 32 random bytes;
 *                         D: the address and port the computer dialled, as the phone saw it;
 *                         S: the address the computer should keep (see Net.stableAddress)
 *   phone    -> computer  c = H(commit-tag || K || Np || D || S)
 *   computer -> phone     pair-reveal-v2(Nh)                    Nh: 32 random bytes
 *   phone    -> computer  K, Np, D, S                           computer checks c, and that
 *                                                               D is the address IT dialled
 *   both show             code = H(code-tag || K || Np || Nh || D || S) as 6 digits
 *
 * The phone is bound to (K, Np, D, S) before it sees Nh, and the computer picks Nh before it
 * sees Np. Someone in the middle must commit to its own values before learning Nh, and must
 * hand the real phone an Nh'' before learning Np: the codes then match by chance, one time in
 * a million. The person TYPES the phone's code into the computer, so it is really compared.
 *
 * D closes the relay that version 1 left open: a device that answered discovery first and
 * passed every byte through unchanged got the real key pinned, but with ITS OWN address in
 * sudo's configuration -- a permanent man in the middle. Now the computer refuses unless the
 * address the phone saw itself being dialled on is the address the computer dialled.
 *
 * After pair-done, while the pairing screen is still open, the computer may ask once more, for
 * attest-v1: the Keystore's attestation chain for the key just made. This is how the computer
 * learns the key lives in the phone's secure hardware rather than taking the phone's word for
 * it (see [attestChallenge] for what ties the chain to THIS pairing). The chain is public data
 * and nothing is signed; it is served for that one key only, and only then.
 *
 * One key per computer: a signature made for one computer is useless on another, and the
 * approval screen names the computer that owns the key, so a request relayed from elsewhere
 * cannot borrow a familiar name. Nothing secret is exchanged: K is public and the nonces are
 * single-use. Pairing never signs anything and is not on the sudo path.
 *
 * All fields are SSH strings (length-prefixed), so no two different inputs hash the same.
 *
 * PAIRING BY QR CODE (qr-v1, 1.7). The computer shows a code; the phone's camera opens it as a
 * link to this app ([QrLink]): a secret S of [QR_SECRET_BYTES] random bytes, and the computer's
 * name. S then stands in for the person comparing codes: whoever knows it is the person at that
 * screen, and nobody else can know it. Nh, Np, K, D and S as above; S_ is the secret.
 *
 *   computer -> phone     pair-qr-hello-v1(H(hello-tag || S_))   "is it you?": SUCCESS only from
 *                                                                the phone that scanned S_
 *   computer -> phone     pair-qr-v1(Nh, macC)                   macC = HMAC(S_, c-tag || Nh || R)
 *                                                                R: where the computer dialled
 *   phone                 checks macC with D for R: what it saw itself dialled on. A relay that
 *                         answered in its place dialled it from elsewhere, and fails here.
 *                         A message that fails is refused and changes nothing: without S_ nobody
 *                         can cancel, spend or slow a pairing.
 *   phone    -> computer  K, Np, D, S, macP                      macP = HMAC(S_, p-tag || Nh || K
 *                                                                       || Np || D || S)
 *   computer              checks macP and D == R, then:
 *   computer -> phone     pair-qr-done-v1(Nh, macD)              macD = HMAC(S_, d-tag || Nh || K)
 *                         on the same connection; then attest-v1 exactly as above.
 *
 * Unlike the code, both directions are authenticated, so pair-qr-done proves the computer
 * holding S_ finished. A second VALID commit still stops the pairing (someone else holds S_), and
 * the new computer still starts PENDING. What it cannot help: anyone who sees the computer's
 * screen holds S_ as much as its owner does. That is why the code stays, and why the computer
 * makes a new S_ for every attempt and every two minutes.
 */
object Pairing {

    /** ssh-agent extension names (SSH_AGENTC_EXTENSION, draft-miller-ssh-agent §3.8).
     *  Version 2: version 1 (one key for every computer, no address binding) is refused. */
    const val EXT_COMMIT = "pair-commit-v2@sudostamp"
    const val EXT_REVEAL = "pair-reveal-v2@sudostamp"
    const val EXT_DONE = "pair-done-v2@sudostamp"

    /** After DONE, while the pairing is still open: the attestation chain of the key just made
     *  (leaf first), for the computer to check against Google's roots. Not in the sudo path. */
    const val EXT_ATTEST = "attest-v1@sudostamp"

    /** Pairing by QR code (qr-v1, see the class comment). */
    const val EXT_QR_HELLO = "pair-qr-hello-v1@sudostamp"
    const val EXT_QR_COMMIT = "pair-qr-v1@sudostamp"
    const val EXT_QR_DONE = "pair-qr-done-v1@sudostamp"
    const val QR_SECRET_BYTES = 16

    /** Version 1's first message: recognised only to tell the person their installer is old. */
    const val EXT_COMMIT_V1 = "pair-commit@sudostamp"

    const val NONCE_BYTES = 32
    const val CODE_DIGITS = 6

    /** An endpoint on the wire: 16 address bytes (IPv4 as ::ffff:a.b.c.d) and a 2-byte port. */
    const val ENDPOINT_BYTES = 18

    /** How long one arming lasts: the code on screen, and the window in which a second
     *  computer's attempt cancels a pairing that just finished. */
    const val CODE_TTL_MS = 120_000L

    private val COMMIT_TAG = "sudostamp-pair-commit-v2\u0000".toByteArray(Charsets.US_ASCII)
    private val CODE_TAG = "sudostamp-pair-code-v2\u0000".toByteArray(Charsets.US_ASCII)
    private val ATTEST_TAG = "sudostamp-attest-challenge-v1\u0000".toByteArray(Charsets.US_ASCII)
    private val QR_HELLO_TAG = "sudostamp-qr-hello-v1\u0000".toByteArray(Charsets.US_ASCII)
    private val QR_C_TAG = "sudostamp-qr-commit-v1\u0000".toByteArray(Charsets.US_ASCII)
    private val QR_P_TAG = "sudostamp-qr-phone-v1\u0000".toByteArray(Charsets.US_ASCII)
    private val QR_D_TAG = "sudostamp-qr-done-v1\u0000".toByteArray(Charsets.US_ASCII)

    fun qrHello(secret: ByteArray): ByteArray = sha256(QR_HELLO_TAG, secret)

    fun qrCommitMac(secret: ByteArray, hostNonce: ByteArray, reached: ByteArray): ByteArray =
        hmac(secret, QR_C_TAG, hostNonce, reached)

    fun qrPhoneMac(
        secret: ByteArray, hostNonce: ByteArray, keyBlob: ByteArray, phoneNonce: ByteArray,
        dialled: ByteArray, stable: ByteArray,
    ): ByteArray = hmac(secret, QR_P_TAG, hostNonce, keyBlob, phoneNonce, dialled, stable)

    fun qrDoneMac(secret: ByteArray, hostNonce: ByteArray, keyBlob: ByteArray): ByteArray =
        hmac(secret, QR_D_TAG, hostNonce, keyBlob)

    /** Equal, in time that does not depend on where they differ. */
    fun same(a: ByteArray?, b: ByteArray?): Boolean = a != null && b != null && MessageDigest.isEqual(a, b)

    fun commitment(keyBlob: ByteArray, phoneNonce: ByteArray, dialled: ByteArray, stable: ByteArray): ByteArray =
        sha256(COMMIT_TAG, keyBlob, phoneNonce, dialled, stable)

    /**
     * The attestation challenge of one pairing: H(tag || Np || D || S). The Keystore signs the
     * challenge into the key's attestation certificate, so a chain made for another pairing (a
     * real phone's, replayed by someone claiming to be it) carries a different challenge and the
     * computer refuses it. It cannot include the key or the computer's nonce: the key does not
     * exist yet when the challenge must be given, and Nh arrives after the key is made. Np is
     * fresh per pairing, which is what makes it single-use; D and S pin it to this phone's
     * addresses. The computer recomputes it from what the reveal handed over.
     */
    fun attestChallenge(phoneNonce: ByteArray, dialled: ByteArray, stable: ByteArray): ByteArray =
        sha256(ATTEST_TAG, phoneNonce, dialled, stable)

    /** The 6-digit code, zero-padded. The first 8 hash bytes as an unsigned number mod 10^6:
     *  the bias from 2^64 not being a multiple of 10^6 is below 10^-13. */
    fun code(keyBlob: ByteArray, phoneNonce: ByteArray, hostNonce: ByteArray, dialled: ByteArray, stable: ByteArray): String {
        val h = sha256(CODE_TAG, keyBlob, phoneNonce, hostNonce, dialled, stable)
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (h[i].toLong() and 0xFF)
        return java.lang.Long.remainderUnsigned(v, 1_000_000L).toString().padStart(CODE_DIGITS, '0')
    }

    /** "482913" -> "482 913", the way both screens show it. */
    fun spaced(code: String): String = code.substring(0, 3) + " " + code.substring(3)

    /**
     * The computer's name as shown on the phone: printable ASCII only, at most 64 characters.
     * It comes off the network, so it is display text and nothing more.
     */
    fun cleanLabel(raw: ByteArray): String =
        String(raw, Charsets.US_ASCII).filter { it in ' '..'~' }.trim().take(64).ifEmpty { "a computer" }

    /** Tag, then each part as an SSH string. */
    private fun framed(tag: ByteArray, parts: Array<out ByteArray>): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(tag)
        for (p in parts) {
            o.write(byteArrayOf((p.size ushr 24).toByte(), (p.size ushr 16).toByte(), (p.size ushr 8).toByte(), p.size.toByte()))
            o.write(p)
        }
        return o.toByteArray()
    }

    private fun sha256(tag: ByteArray, vararg parts: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(framed(tag, parts))

    private fun hmac(key: ByteArray, tag: ByteArray, vararg parts: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(framed(tag, parts))
        }
}
