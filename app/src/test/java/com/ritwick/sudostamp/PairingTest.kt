package com.ritwick.sudostamp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pairing: the code derivation (which must agree byte for byte with tools/pair.py) and the
 * phone's one-attempt-per-tap state machine, including the attacks it exists to stop.
 */
class PairingTest {

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    // Test vectors produced by tools/pair.py. If either side changes, both must.
    private val key = hex(
        "0000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041" +
            "040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
            "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
    )
    private val np = ByteArray(32) { it.toByte() }
    private val nh = ByteArray(32) { (it + 32).toByte() }
    /** pair.endpoint(("192.168.1.20", 7777)) and (("fd6c:5c93:23:1f7e:445b:9bff:fe36:628a", 7777)) */
    private val dialled = hex("00000000000000000000ffffc0a801141e61")
    private val stable = hex("fd6c5c9300231f7e445b9bfffe36628a1e61")

    @Test
    fun `commitment and code match the Python implementation`() {
        assertArrayEquals(hex("c37c3aedabc70facaf31d565dcc8c9748644785dd89bec2d40c61b35cddd492c"),
            Pairing.commitment(key, np, dialled, stable))
        assertEquals("397004", Pairing.code(key, np, nh, dialled, stable))
        assertEquals("303376", Pairing.code(key, np, ByteArray(32), dialled, stable))
    }

    @Test
    fun `the code covers the addresses - a relay changes it`() {
        // A relay that reports the phone's real dialled address is caught by the computer's own
        // address check; one that reports its own would need a code for different inputs.
        assertEquals("238409", Pairing.code(key, np, nh, dialled, dialled))
        assertTrue(Pairing.code(key, np, nh, dialled, stable) != Pairing.code(key, np, nh, dialled, dialled))
    }

    @Test
    fun `endpoints encode like the Python side`() {
        val v4 = java.net.InetAddress.getByName("192.168.1.20")
        val v6 = java.net.InetAddress.getByName("fd6c:5c93:23:1f7e:445b:9bff:fe36:628a")
        assertArrayEquals(dialled, Net.endpoint(v4, 7777))
        assertArrayEquals(stable, Net.endpoint(v6, 7777))
        assertEquals(Pairing.ENDPOINT_BYTES, Net.endpoint(v4, 1).size)
    }

    @Test
    fun `labels from the network are made safe to display`() {
        // Control characters (newlines, the ESC of a terminal escape) are dropped; what is left
        // is inert text.
        assertEquals("edith[2J", Pairing.cleanLabel("edith\n\u001b[2J".toByteArray()))
        assertEquals("a computer", Pairing.cleanLabel(ByteArray(0)))
        assertEquals(64, Pairing.cleanLabel(ByteArray(200) { 'x'.code.toByte() }).length)
    }

    // ------------------------------------------------------------- state machine

    private var t = 0L
    private var nonce = 0
    private var made = 0
    private fun session() = PairingSession({ t }, { n -> ByteArray(n) { (nonce + it).toByte() }.also { nonce += 100 } })
    private val newKey = { PairingSession.NewKey("%016x".format(++made), key) }
    private fun PairingSession.commit(client: String, conn: Long) =
        commit(client, conn, "edith".toByteArray(), dialled, stable, newKey)

    @Test
    fun `one honest pairing runs commit, reveal, code, done`() {
        val p = session()
        p.arm()
        val c = p.commit("10.0.0.2", 1)!!
        val v = p.reveal("10.0.0.2", 1, nh)!!
        assertArrayEquals(key, v.keyBlob)
        assertArrayEquals(dialled, v.dialled)
        assertArrayEquals(stable, v.stable)
        assertArrayEquals(Pairing.commitment(v.keyBlob, v.phoneNonce, v.dialled, v.stable), c)
        assertEquals(PairingSession.State.CODE, p.view().state)
        assertEquals(Pairing.code(v.keyBlob, v.phoneNonce, nh, dialled, stable), p.view().code)
        assertEquals("0000000000000001", p.done("10.0.0.2", nh))
        assertEquals(PairingSession.State.DONE, p.view().state)
        assertEquals("a finished pairing's key is kept", emptyList<String>(), p.drainDiscarded())
        p.disarm()
        assertEquals("and kept when the screen closes", emptyList<String>(), p.drainDiscarded())
    }

    @Test
    fun `nothing is accepted unless the user armed pairing`() {
        assertNull(session().commit("10.0.0.2", 1))
        assertEquals("no key is made for a refused commit", 0, made)
    }

    @Test
    fun `a malformed endpoint is refused before a key is made`() {
        val p = session()
        p.arm()
        assertNull(p.commit("10.0.0.2", 1, ByteArray(0), ByteArray(4), stable, newKey))
        assertEquals(0, made)
    }

    @Test
    fun `one exchange per arming - the grinding attack gets one try`() {
        // Someone in the middle who knows the code the COMPUTER expects would repeat pairing
        // with fresh phone nonces until the phone shows that code. The second commit must not
        // produce a new code; it must stop the pairing visibly, and its key is thrown away.
        val p = session()
        p.arm()
        p.commit("10.0.0.66", 1)!!
        p.reveal("10.0.0.66", 1, nh)!!
        assertNull(p.commit("10.0.0.66", 2))
        assertEquals(PairingSession.State.INTERRUPTED, p.view().state)
        assertNull("no code survives an interruption", p.view().code)
        assertNull("and nothing more is accepted", p.commit("10.0.0.66", 3))
        assertEquals(listOf("0000000000000001"), p.drainDiscarded())
    }

    @Test
    fun `a second computer committing mid-pairing interrupts it`() {
        val p = session()
        p.arm()
        p.commit("10.0.0.2", 1)!!
        assertNull(p.commit("10.0.0.66", 9))
        assertEquals(PairingSession.State.INTERRUPTED, p.view().state)
        assertEquals(listOf("0000000000000001"), p.drainDiscarded())
    }

    @Test
    fun `an attacker who finishes first is cancelled by the real computer arriving`() {
        // pair-done proves nothing about the person: whoever ran commit and reveal knows its
        // own nonce. So an attacker can race the person's computer and finish. The person's
        // computer then commits within the same arming -- and that throws the attacker's key
        // away instead of being refused quietly.
        val p = session()
        p.arm()
        p.commit("10.0.0.66", 1)!!
        p.reveal("10.0.0.66", 1, nh)!!
        assertEquals("0000000000000001", p.done("10.0.0.66", nh))
        assertNull(p.commit("10.0.0.2", 2))
        assertEquals(PairingSession.State.INTERRUPTED, p.view().state)
        assertEquals(listOf("0000000000000001"), p.drainDiscarded())
    }

    @Test
    fun `after the arming window a late commit is only refused`() {
        val p = session()
        p.arm()
        p.commit("10.0.0.2", 1)!!
        p.reveal("10.0.0.2", 1, nh)!!
        p.done("10.0.0.2", nh)!!
        t += Pairing.CODE_TTL_MS
        assertNull(p.commit("10.0.0.66", 2))
        assertEquals(PairingSession.State.DONE, p.view().state)
        assertEquals(emptyList<String>(), p.drainDiscarded())
    }

    @Test
    fun `reveal must come on the committing connection, once, with a full nonce`() {
        val p = session()
        p.arm()
        p.commit("10.0.0.2", 1)!!
        assertNull("short nonce", p.reveal("10.0.0.2", 1, ByteArray(8)))
        assertNotNull(p.reveal("10.0.0.2", 1, nh))
        assertNull("only once", p.reveal("10.0.0.2", 1, nh))

        val q = session()
        q.arm()
        q.commit("10.0.0.2", 1)!!
        assertNull(q.reveal("10.0.0.2", 2, nh))
        assertEquals(PairingSession.State.INTERRUPTED, q.view().state)
    }

    @Test
    fun `done only counts for this pairing`() {
        val p = session()
        p.arm()
        p.commit("10.0.0.2", 1)!!
        p.reveal("10.0.0.2", 1, nh)!!
        assertNull(p.done("10.0.0.66", nh))
        assertNull(p.done("10.0.0.2", ByteArray(32)))
        assertEquals(PairingSession.State.CODE, p.view().state)
    }

    @Test
    fun `an armed pairing expires and its key is thrown away`() {
        val p = session()
        p.arm()
        p.commit("10.0.0.2", 1)!!
        t += Pairing.CODE_TTL_MS
        assertEquals(PairingSession.State.EXPIRED, p.view().state)
        assertNull(p.reveal("10.0.0.2", 1, nh))
        assertEquals(listOf("0000000000000001"), p.drainDiscarded())
    }

    @Test
    fun `cancelling disarms and throws an unfinished key away`() {
        val p = session()
        p.arm()
        p.commit("10.0.0.2", 1)!!
        p.disarm()
        assertNull(p.commit("10.0.0.2", 2))
        assertEquals(PairingSession.State.IDLE, p.view().state)
        assertEquals(listOf("0000000000000001"), p.drainDiscarded())
    }

    @Test
    fun `discoverable only until a computer commits`() {
        val p = session()
        p.arm()
        assertTrue(p.discoverable())
        p.commit("10.0.0.2", 1)!!
        assertEquals(false, p.discoverable())
        assertTrue("but still armed", p.armed())
    }
}
