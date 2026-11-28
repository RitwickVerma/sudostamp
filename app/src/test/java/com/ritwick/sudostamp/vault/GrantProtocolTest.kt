package com.ritwick.sudostamp.vault

import com.ritwick.sudostamp.AgentProtocol
import com.ritwick.sudostamp.Hpke
import com.ritwick.sudostamp.SecretProtocol
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/** grant-request-v1 parsing and its transcripts (docs/design/vault-grant.md 4). */
class GrantProtocolTest {

    private fun strings(vararg parts: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        for (p in parts) {
            o.write(byteArrayOf((p.size ushr 24).toByte(), (p.size ushr 16).toByte(), (p.size ushr 8).toByte(), p.size.toByte()))
            o.write(p)
        }
        return o.toByteArray()
    }

    /** A reader positioned where AgentService hands it over: type byte and extension name consumed. */
    private fun reader(body: ByteArray) = AgentProtocol.Reader(byteArrayOf(27) + body).also { it.skipType() }

    private val sig = byteArrayOf(0x30) + ByteArray(69) { it.toByte() }
    private val k = ByteArray(104) { (it * 7).toByte() }
    private val np = ByteArray(32) { it.toByte() }

    private fun parse(vararg parts: ByteArray) = GrantProtocol.parseRequest(reader(strings(*parts)))

    @Test
    fun parsesAValidRequest() {
        val q = parse("login.example.com".toByteArray(), sig)!!
        assertEquals("login.example.com", q.host)
        assertArrayEquals(sig, q.sigH)
    }

    @Test
    fun refusesTrailingBytes() {
        assertNull(GrantProtocol.parseRequest(reader(strings("example.com".toByteArray(), sig) + byteArrayOf(0))))
        assertNull(parse("example.com".toByteArray(), sig, ByteArray(0)))
    }

    @Test
    fun refusesMissingOrTruncatedFields() {
        assertNull(parse("example.com".toByteArray()))
        assertNull(parse())
        val whole = strings("example.com".toByteArray(), sig)
        for (n in 0 until whole.size) assertNull("prefix $n", GrantProtocol.parseRequest(reader(whole.copyOf(n))))
    }

    @Test
    fun refusesBadHosts() {
        for (h in listOf("", "Example.com", "example.com.", "com", "1.2.3.4", "ex\u00e4mple.com", "example.com\u0000")) {
            assertNull(h, parse(h.toByteArray(Charsets.UTF_8), sig))
        }
        assertNull(parse(ByteArray(254) { 'a'.code.toByte() }, sig))
    }

    @Test
    fun refusesBadSignatures() {
        assertNull(parse("example.com".toByteArray(), ByteArray(0)))
        assertNull(parse("example.com".toByteArray(), byteArrayOf(0x31) + ByteArray(69)))
        assertNull(parse("example.com".toByteArray(), byteArrayOf(0x30) + ByteArray(72)))
        assertNotNull(parse("example.com".toByteArray(), byteArrayOf(0x30) + ByteArray(71)))
    }

    @Test
    fun transcriptIsTagThenFramedFields() {
        val q = parse("example.com".toByteArray(), sig)!!
        val t = GrantProtocol.transcript(k, np, q)
        val expected = "sudostamp-grant-request-v1\u0000".toByteArray(Charsets.US_ASCII) + strings(k, np, "example.com".toByteArray())
        assertArrayEquals(expected, t)
        val a = GrantProtocol.answerMessage(t, "cipher-id".toByteArray())
        assertArrayEquals("sudostamp-grant-answer-v1\u0000".toByteArray(Charsets.US_ASCII) + strings(t, "cipher-id".toByteArray()), a)
        assertTrue("an answer must never be 32 bytes (a pam_rssh challenge)", a.size > AgentProtocol.CHALLENGE_BYTES)
        assertTrue(GrantProtocol.answerMessage(ByteArray(0), ByteArray(0)).size > AgentProtocol.CHALLENGE_BYTES)
    }

    @Test
    fun tagsAreDistinctFromEveryOtherTag() {
        // Every domain-separation tag in the app (SecretProtocol, Pairing), as literals.
        val others = listOf("sudostamp-secret-request-v1", "sudostamp-secret-answer-v1", "sudostamp-secret-v1",
            "sudostamp-pair-commit-v2", "sudostamp-pair-code-v2", "sudostamp-attest-challenge-v1", "sudostamp-qr-hello-v1",
            "sudostamp-qr-hello-reply-v1", "sudostamp-qr-commit-v1", "sudostamp-qr-phone-v1", "sudostamp-qr-done-v1")
            .map { "$it\u0000".toByteArray(Charsets.US_ASCII) }
        val mine = listOf(GrantProtocol.REQUEST_TAG, GrantProtocol.ANSWER_TAG)
        assertFalse(mine[0].contentEquals(mine[1]))
        for (m in mine) for (o in others) {
            val n = minOf(m.size, o.size)
            assertFalse("${String(m)} shares a prefix with ${String(o)}", m.copyOf(n).contentEquals(o.copyOf(n)))
        }
    }

    @Test
    fun signatureOverTranscriptBindsTheHost() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val h = Hpke.encode(kp.public as ECPublicKey)
        val unsigned = parse("example.com".toByteArray(), sig)!!
        val t = GrantProtocol.transcript(k, np, unsigned)
        val s = Signature.getInstance("SHA256withECDSA").run { initSign(kp.private); update(t); sign() }
        val q = parse("example.com".toByteArray(), s)!!
        assertTrue(SecretProtocol.verifyHost(h, GrantProtocol.transcript(k, np, q), q.sigH))
        val other = parse("login.example.com".toByteArray(), s)!!
        assertFalse(SecretProtocol.verifyHost(h, GrantProtocol.transcript(k, np, other), other.sigH))
        assertFalse(SecretProtocol.verifyHost(h, GrantProtocol.transcript(k, ByteArray(32), q), q.sigH))
    }

    @Test
    fun answerFrame() {
        val f = GrantProtocol.answerFrame("id".toByteArray(), sig)
        assertEquals(AgentProtocol.SSH2_AGENT_SUCCESS, f[0].toInt())
        assertArrayEquals(strings("id".toByteArray(), sig), f.copyOfRange(1, f.size))
    }
}
