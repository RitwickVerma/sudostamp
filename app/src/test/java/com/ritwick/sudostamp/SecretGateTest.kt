package com.ritwick.sudostamp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.Base64

/**
 * The per-connection rules of a secret request (SecretGate): one hello, one request, the nonce
 * spent whatever happens, and nothing past a computer that cannot be told apart from the LAN.
 * The signed request is the Python one from SecretProtocolTest (nonce 00..1f).
 */
class SecretGateTest {

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private val k = hex(
        "0000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041" +
            "040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
            "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
    )
    private val np = ByteArray(32) { it.toByte() }
    private val pkR = hex("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0")
    private val h = hex("04b80a6328f448a8796d12339d9c16f4f7c057ba2c7684b396f55b7b95ae6d933c4e308f4b1237f4d7d3798f8c1a834debefacfb70c020e5b2c970916b667e85a8")
    private val sigH = hex("3046022100c53aa0d0e54ea877e1c98bb46a9ce771a773aea980e3f06e5c1e911371f017ce022100a945dd83efc145975732b72c0af9adef935e1a4e2805fec0b985e742ad028d82")

    private val host = Host("0123456789abcdef", "build-box", 1L, true, "192.0.2.7", Base64.getEncoder().encodeToString(h))
    private val oldHost = host.copy(hostKey = null)

    private fun request(): SecretProtocol.Request {
        val o = ByteArrayOutputStream()
        for (p in listOf("input".toByteArray(), "restic".toByteArray(), "weekly backup ✓".toByteArray(), pkR, sigH)) {
            o.write(byteArrayOf((p.size ushr 24).toByte(), (p.size ushr 16).toByte(), (p.size ushr 8).toByte(), p.size.toByte()))
            o.write(p)
        }
        return SecretProtocol.parseRequest(AgentProtocol.Reader(byteArrayOf(27) + o.toByteArray()).also { it.skipType() })!!
    }

    private fun gate(nonce: ByteArray = np) = SecretGate { nonce.copyOf(it) }
    private val find: (ByteArray) -> Host? = { if (it.contentEquals(k)) host else null }
    private val noLimit: (String) -> Refusal? = { null }
    private val blob: (Host) -> ByteArray? = { k }

    @Test
    fun `hello then a request signed over this nonce is put to the person`() {
        val g = gate()
        val hi = g.hello(k, find, noLimit) as SecretGate.Hello.Ok
        assertArrayEquals(np, hi.nonce)
        val ok = g.request(request(), blob) as SecretGate.Ask.Ok
        assertSame(host, ok.host)
        assertEquals("restic", ok.request.name)
        assertArrayEquals(SecretProtocol.transcript(k, np, ok.request), ok.t)
    }

    @Test
    fun `one request per hello - the nonce is spent even by a refused one`() {
        val g = gate()
        g.hello(k, find, noLimit)
        g.request(request(), blob)
        assertTrue("second request", g.request(request(), blob) is SecretGate.Ask.Refused)

        val g2 = gate()
        g2.hello(k, find, noLimit)
        assertTrue("malformed", g2.request(null, blob) is SecretGate.Ask.Refused)
        assertTrue("then the good one", g2.request(request(), blob) is SecretGate.Ask.Refused)
    }

    @Test
    fun `a request without a hello, or a second hello, is refused`() {
        assertTrue(gate().request(request(), blob) is SecretGate.Ask.Refused)
        val g = gate()
        g.hello(k, find, noLimit)
        val again = g.hello(k, find, noLimit) as SecretGate.Hello.Refused
        assertEquals(Refusal.BAD_REQUEST, again.why)
    }

    @Test
    fun `a captured request replayed on another connection fails its signature`() {
        val g = gate(ByteArray(32) { 7 })
        g.hello(k, find, noLimit)
        val r = g.request(request(), blob) as SecretGate.Ask.Refused
        assertEquals(Refusal.BAD_REQUEST, r.why)
        assertSame(host, r.host)
    }

    @Test
    fun `a request signed for another phone key fails`() {
        val g = gate()
        g.hello(k, find, noLimit)
        assertTrue(g.request(request()) { k + 0 } is SecretGate.Ask.Refused)
    }

    @Test
    fun `unknown key, a computer paired before 2_0, and the limiter refuse the hello`() {
        val unknown = gate().hello(k + 0, find, noLimit) as SecretGate.Hello.Refused
        assertEquals(Refusal.UNKNOWN_KEY, unknown.why)
        assertNull(unknown.host)
        assertEquals(Refusal.UNKNOWN_KEY, (gate().hello(null, find, noLimit) as SecretGate.Hello.Refused).why)
        val old = gate().hello(k, { oldHost }, noLimit) as SecretGate.Hello.Refused
        assertEquals(Refusal.NO_HOST_KEY, old.why)
        val cooling = gate().hello(k, find) { Refusal.COOLDOWN } as SecretGate.Hello.Refused
        assertEquals(Refusal.COOLDOWN, cooling.why)
    }

    @Test
    fun `a computer not yet approved once cannot ask for a secret`() {
        // A pairing proves which key was pinned, not who paired (a race on the pairing code).
        // Such a computer must first get one sudo approved, with the new-computer warning.
        val pending = gate().hello(k, { host.copy(confirmed = false) }, noLimit) as SecretGate.Hello.Refused
        assertEquals(Refusal.PENDING, pending.why)
        assertEquals(host.id, pending.host?.id)
    }

    @Test
    fun `a refused hello leaves nothing to spend`() {
        val g = gate()
        g.hello(k, find) { Refusal.COOLDOWN }
        assertTrue(g.request(request(), blob) is SecretGate.Ask.Refused)
    }
}
