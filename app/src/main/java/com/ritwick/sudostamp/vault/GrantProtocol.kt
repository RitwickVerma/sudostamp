package com.ritwick.sudostamp.vault

import com.ritwick.sudostamp.AgentProtocol
import com.ritwick.sudostamp.Pairing
import java.io.IOException

/**
 * `sudostamp grant <host>` on the wire (docs/design/vault-grant.md 4): one ssh-agent extension on
 * a connection that has already done `secret-hello-v1` (SecretProtocol), so the phone holds this
 * connection's nonce Np and the computer's pinned host key H.
 *
 *     computer -> phone  grant-request-v1   string host, string sigH
 *                                           sigH = ECDSA-P256-SHA256(H, T), T = tag-grant || K || Np || host
 *     phone -> computer  SUCCESS string id, string sigK | FAILURE
 *                                           sigK = ECDSA-P256-SHA256(K, tag-grant-ans || T || id)
 *
 * Parsing and T only: the signature check, the limiter and the Binder call to `:vault` live with
 * their callers. Pure: no Android.
 */
object GrantProtocol {

    const val EXT_REQUEST = "grant-request-v1@sudostamp"

    /** DER ECDSA over P-256 is at most 72 bytes. */
    private const val MAX_SIG_BYTES = 72

    /**
     * Domain separation. New tags, never SecretProtocol's: a grant transcript can never verify as
     * a secret request, and a grant answer can never be replayed as an `input` answer or the other
     * way round. Each ends in NUL so no tag is a prefix of another tag plus data.
     */
    internal val REQUEST_TAG = "sudostamp-grant-request-v1\u0000".toByteArray(Charsets.US_ASCII)
    internal val ANSWER_TAG = "sudostamp-grant-answer-v1\u0000".toByteArray(Charsets.US_ASCII)

    class Request(
        /** A host [GrantHost.parse] accepted: the only thing the computer chooses. */
        val host: String,
        val sigH: ByteArray,
    )

    /**
     * The request, or null for anything that is not exactly one: trailing bytes, a host that
     * [GrantHost.parse] refuses, a signature that cannot be DER. Never throws. The signature is
     * NOT checked here (SecretProtocol.verifyHost over [transcript]).
     */
    fun parseRequest(r: AgentProtocol.Reader): Request? {
        val (host, sigH) = try {
            List(2) { r.blob() }.takeIf { r.atEnd() } ?: return null
        } catch (e: IOException) {
            return null
        }
        val h = GrantHost.parse(host) ?: return null
        if (sigH.isEmpty() || sigH.size > MAX_SIG_BYTES || sigH[0] != 0x30.toByte()) return null
        return Request(h, sigH)
    }

    /** T: what H signs, and what the answer is bound to. Each part length-prefixed (Pairing.framed). */
    fun transcript(phoneKey: ByteArray, nonce: ByteArray, q: Request): ByteArray =
        Pairing.framed(REQUEST_TAG, arrayOf(phoneKey, nonce, q.host.toByteArray(Charsets.US_ASCII)))

    /**
     * What K signs for an answer. Always longer than the 32 bytes the sudo path signs (the tag
     * alone is 26), so it is never a pam_rssh challenge, and AgentProtocol.refusal, which refuses
     * every other size, never signs one of these on the sudo path.
     */
    fun answerMessage(t: ByteArray, id: ByteArray): ByteArray = Pairing.framed(ANSWER_TAG, arrayOf(t, id))

    /** The SUCCESS frame body: the cipher id, then K's DER signature. */
    fun answerFrame(id: ByteArray, sigDer: ByteArray): ByteArray = AgentProtocol.success(id, sigDer)
}
