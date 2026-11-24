package com.ritwick.sudostamp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * The secret request (SecretProtocol). Vectors come from tools/secret.py; if either side changes,
 * both must (tools/test/test_secret.py holds the same numbers).
 */
class SecretProtocolTest {

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)

    private val k = hex(
        "0000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041" +
            "040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
            "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
    )
    private val np = ByteArray(32) { it.toByte() }
    /** RFC 9180 A.3.1's pkRm, standing in for the computer's per-request key. */
    private val pkR = hex("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0")
    /** The test host key H (scalar = SHA-256("sudostamp test host key")). */
    private val h = hex("04b80a6328f448a8796d12339d9c16f4f7c057ba2c7684b396f55b7b95ae6d933c4e308f4b1237f4d7d3798f8c1a834debefacfb70c020e5b2c970916b667e85a8")
    private val why = "weekly backup ✓".toByteArray(Charsets.UTF_8)
    /** One signature by H over T, made by tools/secret.py (ECDSA is randomised: any valid one will do). */
    private val sigH = hex("3046022100c53aa0d0e54ea877e1c98bb46a9ce771a773aea980e3f06e5c1e911371f017ce022100a945dd83efc145975732b72c0af9adef935e1a4e2805fec0b985e742ad028d82")

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

    private fun request(
        kind: ByteArray = "input".toByteArray(), name: ByteArray = "restic".toByteArray(), w: ByteArray = why,
        key: ByteArray = pkR, sig: ByteArray = sigH,
    ) = strings(kind, name, w, key, sig)

    private fun parsed() = SecretProtocol.parseRequest(reader(request()))!!

    @Test
    fun `transcript, info and answer match the Python implementation`() {
        val t = SecretProtocol.transcript(k, np, parsed())
        assertEquals(281, t.size)
        assertArrayEquals(hex("b37db54d5eb1d176c20a60d4b7a01353791898f179ea42052c1f7be560a2980b"), sha(t))
        assertArrayEquals(hex("7375646f7374616d702d7365637265742d763100b37db54d5eb1d176c20a60d4b7a01353791898f179ea42052c1f7be560a2980b"),
            SecretProtocol.info(t))
        val enc = hex("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4")
        val ct = hex("5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434")
        assertArrayEquals(hex("153be01b755c4b0bc268c3854dac367bf80bbbcf9f6ed9ec44ea080901dee2aa"),
            sha(SecretProtocol.answerMessage(t, enc, ct)))
    }

    @Test
    fun `the host signature made in Python verifies, and only over this transcript`() {
        val q = parsed()
        val t = SecretProtocol.transcript(k, np, q)
        assertTrue(SecretProtocol.verifyHost(h, t, q.sigH))
        // Another nonce (a replay on a new connection), another phone key, another key to encrypt to:
        assertFalse(SecretProtocol.verifyHost(h, SecretProtocol.transcript(k, ByteArray(32), q), q.sigH))
        assertFalse(SecretProtocol.verifyHost(h, SecretProtocol.transcript(k + 0, np, q), q.sigH))
        val otherKey = Hpke.encode(java.security.KeyPairGenerator.getInstance("EC").apply {
            initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }.generateKeyPair().public as java.security.interfaces.ECPublicKey)
        val swapped = SecretProtocol.parseRequest(reader(request(key = otherKey)))!!
        assertFalse(SecretProtocol.verifyHost(h, SecretProtocol.transcript(k, np, swapped), q.sigH))
        // Changed words on the screen:
        val reworded = SecretProtocol.parseRequest(reader(request(w = "monthly backup".toByteArray())))!!
        assertFalse(SecretProtocol.verifyHost(h, SecretProtocol.transcript(k, np, reworded), q.sigH))
        // Another computer's key:
        assertFalse(SecretProtocol.verifyHost(pkR, t, q.sigH))
        // Garbage never throws:
        assertFalse(SecretProtocol.verifyHost(ByteArray(65), t, q.sigH))
        assertFalse(SecretProtocol.verifyHost(h, t, byteArrayOf(0x30, 0)))
    }

    @Test
    fun `a well-formed request parses`() {
        val q = parsed()
        assertEquals("input", q.kind)
        assertEquals("restic", q.name)
        assertEquals("weekly backup ✓", q.why)
        assertArrayEquals(why, q.whyRaw)
    }

    @Test
    fun `malformed requests are refused, never thrown`() {
        val bad = listOf(
            request(kind = "unseal".toByteArray()),
            request(kind = "inputx".toByteArray()),
            request(name = ByteArray(0)),
            request(name = "a".repeat(65).toByteArray()),
            request(name = "rest ic".toByteArray()),
            request(name = "restic\n".toByteArray()),
            request(w = ByteArray(0)),
            request(w = "   ".toByteArray()),
            request(w = byteArrayOf(0xC3.toByte(), 0x28)),                       // malformed UTF-8
            request(w = ByteArray(AgentProtocol.MAX_CONTEXT_BYTES + 1) { 'a'.code.toByte() }),
            request(key = pkR.copyOf(64)),
            request(key = pkR.copyOf().also { it[64] = (it[64].toInt() xor 1).toByte() }), // off the curve
            request(sig = ByteArray(0)),
            request(sig = ByteArray(73) { 0x30 }),
            request(sig = byteArrayOf(0x02, 0x01, 0x01)),
            request() + 0,                                                      // trailing byte
            request().copyOf(request().size - 1),                               // truncated
            ByteArray(0),
        )
        for (b in bad) assertNull(SecretProtocol.parseRequest(reader(b)))
    }

    @Test
    fun `the reason is scrubbed for display but signed as sent`() {
        val raw = "backup\u202Eevil".toByteArray()
        val q = SecretProtocol.parseRequest(reader(request(w = raw)))!!
        assertEquals("backup?evil", q.why)
        assertArrayEquals(raw, q.whyRaw)
    }

    @Test
    fun `hello carries exactly one key blob`() {
        assertArrayEquals(k, SecretProtocol.parseHello(reader(strings(k))))
        assertNull(SecretProtocol.parseHello(reader(strings(k) + 0)))
        assertNull(SecretProtocol.parseHello(reader(strings(ByteArray(0)))))
        assertNull(SecretProtocol.parseHello(reader(strings(ByteArray(1025)))))
        assertNull(SecretProtocol.parseHello(reader(ByteArray(3))))
    }

    @Test
    fun `an answer is never a sudo challenge, and a sudo challenge is never an answer`() {
        val t = SecretProtocol.transcript(k, np, parsed())
        val m = SecretProtocol.answerMessage(t, ByteArray(0), ByteArray(0))
        assertTrue(m.size > AgentProtocol.CHALLENGE_BYTES)
        assertNotNull(AgentProtocol.refusalKind(true, m))
        // And the shortest possible answer message is still longer than a challenge.
        assertTrue(SecretProtocol.answerMessage(ByteArray(0), ByteArray(0), ByteArray(0)).size > AgentProtocol.CHALLENGE_BYTES)
    }

    @Test
    fun `answer seals 1 to 1024 bytes and signs exactly what it sends`() {
        val t = SecretProtocol.transcript(k, np, parsed())
        assertNull(SecretProtocol.answer(t, pkR, ByteArray(0)))
        assertNull(SecretProtocol.answer(t, pkR, ByteArray(SecretProtocol.MAX_SECRET_BYTES + 1)))
        assertNotNull(SecretProtocol.answer(t, pkR, ByteArray(SecretProtocol.MAX_SECRET_BYTES)))
        val a = SecretProtocol.answer(t, pkR, "hunter2".toByteArray())!!
        assertArrayEquals(SecretProtocol.answerMessage(t, a.sealed.enc, a.sealed.ct), a.toSign)
        // GCM: ciphertext = plaintext + 16-byte tag; nothing else rides along.
        assertEquals(7 + 16, a.sealed.ct.size)

        val sig = byteArrayOf(0x30, 1, 2)
        val r = AgentProtocol.Reader(SecretProtocol.answerFrame(a, sig))
        assertEquals(AgentProtocol.SSH2_AGENT_SUCCESS, r.type())
        r.skipType()
        assertArrayEquals(a.sealed.enc, r.blob())
        assertArrayEquals(a.sealed.ct, r.blob())
        assertArrayEquals(sig, r.blob())
        assertTrue(r.atEnd())
    }

    @Test
    fun `utf8 encodes like the platform, refuses lone surrogates`() {
        for (v in listOf("hunter2", "p\u00e4ssw\u00f6rd \u2713", "\ud83d\udd11 key", "\u4e2d\u6587\u5bc6\u7801", "")) {
            org.junit.Assert.assertArrayEquals(v, v.toByteArray(Charsets.UTF_8), SecretProtocol.utf8(v.toCharArray()))
        }
        org.junit.Assert.assertNull(SecretProtocol.utf8(charArrayOf('a', '\ud83d')))
        org.junit.Assert.assertNull(SecretProtocol.utf8(charArrayOf('\udd11', 'a')))
    }
}
