package com.ritwick.sudostamp

import java.security.SecureRandom

/**
 * One connection's secret exchange (docs/design/secrets.md §6.3): one hello, then at most one
 * request, verified against this connection's nonce and the computer's host key H. Pure: the
 * service hands in the lookups, so every rule here runs in a JVM test.
 *
 * Every refusal is decided before anything is shown, and says only what the history records.
 */
class SecretGate(private val random: (Int) -> ByteArray = ::randomBytes) {

    sealed class Hello {
        class Ok(val host: Host, val nonce: ByteArray) : Hello()
        class Refused(val why: Refusal, val host: Host?) : Hello()
    }

    sealed class Ask {
        /** Verified: put it to the person. [t] is what the answer is bound to. */
        class Ok(val host: Host, val request: SecretProtocol.Request, val t: ByteArray) : Ask()
        class Refused(val why: Refusal, val host: Host?) : Ask()
    }

    private var helloSeen = false
    private var nonce: ByteArray? = null
    private var host: Host? = null

    /**
     * [k]: the key blob the hello named (null if it did not parse). [find]: the paired computer
     * whose key that is. [limit]: the limiter's verdict for a computer, null to go ahead.
     */
    fun hello(k: ByteArray?, find: (ByteArray) -> Host?, limit: (String) -> Refusal?): Hello {
        if (helloSeen) return Hello.Refused(Refusal.BAD_REQUEST, null)
        helloSeen = true
        val h = k?.let(find) ?: return Hello.Refused(Refusal.UNKNOWN_KEY, null)
        // Paired before 2.0: the phone cannot tell this computer from anything on the LAN.
        if (h.hostKeyBytes() == null) return Hello.Refused(Refusal.NO_HOST_KEY, h)
        // Pairing proves which key the computer pinned, not who paired it (a code race): a
        // computer asks for secrets only after the person has approved one of its requests.
        if (!h.confirmed) return Hello.Refused(Refusal.PENDING, h)
        limit(h.id)?.let { return Hello.Refused(it, h) }
        val n = random(SecretProtocol.NONCE_BYTES)
        nonce = n
        host = h
        return Hello.Ok(h, n.copyOf())
    }

    /** [q]: the parsed request (null if malformed). [keyBlob]: K for a computer. */
    fun request(q: SecretProtocol.Request?, keyBlob: (Host) -> ByteArray?): Ask {
        // Spent by the first request, whatever happens next: one request per hello.
        val n = nonce
        val h = host
        nonce = null
        host = null
        if (n == null || h == null) return Ask.Refused(Refusal.BAD_REQUEST, null)
        val hk = h.hostKeyBytes()
        val k = keyBlob(h)
        if (q == null || hk == null || k == null) return Ask.Refused(Refusal.BAD_REQUEST, h)
        val t = SecretProtocol.transcript(k, n, q)
        if (!SecretProtocol.verifyHost(hk, t, q.sigH)) return Ask.Refused(Refusal.BAD_REQUEST, h)
        return Ask.Ok(h, q, t)
    }
}

private fun randomBytes(n: Int) = ByteArray(n).also { SecureRandom().nextBytes(it) }
