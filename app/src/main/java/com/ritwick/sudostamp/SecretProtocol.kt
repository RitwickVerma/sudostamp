package com.ritwick.sudostamp

import java.io.IOException
import java.security.MessageDigest
import java.security.Signature

/**
 * A program on a paired computer asks for a secret the person types (or fills) on the phone:
 * `sudostamp input` on the computer, docs/design/secrets.md for the why. Two ssh-agent
 * extensions on one connection; tools/secret.py is the other end and shares the vectors
 * (SecretProtocolTest, tools/test/test_secret.py).
 *
 *     computer -> phone  secret-hello-v1    string K                 (which computer)
 *     phone -> computer  SUCCESS string Np | FAILURE                 (Np: this connection's nonce)
 *     computer -> phone  secret-request-v1  string kind, name, why, pkR, sigH
 *                                           sigH = ECDSA-P256-SHA256(H, T)
 *     phone -> computer  SUCCESS string enc, ct, sigK | FAILURE
 *                                           (enc, ct) = HPKE-seal(pkR, info(T), "", value)
 *                                           sigK = ECDSA-P256-SHA256(K, answer(T, enc, ct)), behind the finger
 *
 * WHY THE PHONE NEEDS H: the sudo path is safe against requests from anyone because a signature
 * over pam_rssh's challenge is useless to anyone but the computer that made it. A secret is
 * useful to whoever receives it, so the phone must know the request is from the computer it
 * names: H is that computer's key, pinned at pairing (v3), and it signs over a nonce the phone
 * chose for this connection, so nothing can be replayed. Everything here is pure: no Android.
 */
object SecretProtocol {

    const val EXT_HELLO = "secret-hello-v1@sudostamp"
    const val EXT_REQUEST = "secret-request-v1@sudostamp"

    /** The only kind there is. ("unseal" would be phase 2; not built.) */
    const val KIND_INPUT = "input"

    const val NONCE_BYTES = 32

    /** What is asked for: an identifier, not prose ([why] is the prose). */
    private val NAME = Regex("[A-Za-z0-9._@+-]{1,64}")

    /** The longest value the phone sends, in UTF-8 bytes. A passphrase, not a file. */
    const val MAX_SECRET_BYTES = 1024

    /** A phone key blob is about 104 bytes; anything far bigger is not one. */
    private const val MAX_KEY_BLOB = 1024

    /** DER ECDSA over P-256 is at most 72 bytes. */
    private const val MAX_SIG_BYTES = 72

    private val REQUEST_TAG = "sudostamp-secret-request-v1\u0000".toByteArray(Charsets.US_ASCII)
    private val ANSWER_TAG = "sudostamp-secret-answer-v1\u0000".toByteArray(Charsets.US_ASCII)
    private val INFO_TAG = "sudostamp-secret-v1\u0000".toByteArray(Charsets.US_ASCII)

    class Request(
        val kind: String,
        val name: String,
        /** The reason, as it is shown: strict UTF-8, scrubbed like a sudo description. */
        val why: String,
        /** The reason as sent and signed. */
        val whyRaw: ByteArray,
        /** The computer's HPKE key for this one request. */
        val pkR: ByteArray,
        val sigH: ByteArray,
    )

    /** The K a hello names, or null for anything but exactly one plausible key blob. Never throws. */
    fun parseHello(r: AgentProtocol.Reader): ByteArray? = try {
        val k = r.blob()
        if (!r.atEnd() || k.isEmpty() || k.size > MAX_KEY_BLOB) null else k
    } catch (e: IOException) {
        null
    }

    /**
     * The request, or null for anything that is not exactly one: trailing bytes, another kind, a
     * name that is not an identifier, a reason that is not strict UTF-8 or is empty once scrubbed,
     * a key that is not a P-256 point, a signature that cannot be DER. Never throws. The
     * signature is NOT checked here: see [verifyHost].
     */
    fun parseRequest(r: AgentProtocol.Reader): Request? {
        val parts = try {
            List(5) { r.blob() }.takeIf { r.atEnd() } ?: return null
        } catch (e: IOException) {
            return null
        }
        val (kind, name, whyRaw, pkR, sigH) = parts
        if (String(kind, Charsets.US_ASCII) != KIND_INPUT || kind.size != KIND_INPUT.length) return null
        val n = String(name, Charsets.US_ASCII)
        if (!NAME.matches(n)) return null
        if (whyRaw.size > AgentProtocol.MAX_CONTEXT_BYTES) return null
        val why = AgentProtocol.displayText(whyRaw) ?: return null
        if (runCatching { Hpke.publicKey(pkR) }.isFailure) return null
        if (sigH.isEmpty() || sigH.size > MAX_SIG_BYTES || sigH[0] != 0x30.toByte()) return null
        return Request(KIND_INPUT, n, why, whyRaw, pkR, sigH)
    }

    /** T: what the computer signs, and what the answer and its encryption are bound to. */
    fun transcript(phoneKey: ByteArray, nonce: ByteArray, q: Request): ByteArray =
        Pairing.framed(REQUEST_TAG, arrayOf(phoneKey, nonce, q.kind.toByteArray(Charsets.US_ASCII),
            q.name.toByteArray(Charsets.US_ASCII), q.whyRaw, q.pkR))

    /** True only if [sig] is H's signature over [t]. False for any key or signature that does not parse. */
    fun verifyHost(hostKey: ByteArray, t: ByteArray, sig: ByteArray): Boolean = runCatching {
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(Hpke.publicKey(hostKey))
            update(t)
            verify(sig)
        }
    }.getOrDefault(false)

    /** HPKE info: the request binds the ciphertext. */
    fun info(t: ByteArray): ByteArray = INFO_TAG + MessageDigest.getInstance("SHA-256").digest(t)

    /**
     * What K signs for an answer. Always longer than the 32 bytes the sudo path signs (the tag
     * alone is 27), so no answer is a pam_rssh challenge, and the sudo path, which refuses any
     * other size, can never be made to sign one of these.
     */
    fun answerMessage(t: ByteArray, enc: ByteArray, ct: ByteArray): ByteArray =
        Pairing.framed(ANSWER_TAG, arrayOf(t, enc, ct))
}
