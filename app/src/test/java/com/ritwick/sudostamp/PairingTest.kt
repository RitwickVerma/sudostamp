package com.ritwick.sudostamp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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

    @Test
    fun `commitment and code match the Python implementation`() {
        assertArrayEquals(hex("b21ad7bb7cf583fe468b45b0e7c3fccc1528092143ece4624334806c9aa8fc58"),
            Pairing.commitment(key, np))
        assertEquals("613473", Pairing.code(key, np, nh))
        assertEquals("350185", Pairing.code(key, np, ByteArray(32)))
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
    private fun session() = PairingSession({ t }, { n -> ByteArray(n) { (nonce + it).toByte() }.also { nonce += 100 } })

    @Test
    fun `one honest pairing runs commit, reveal, code, done`() {
        val p = session()
        p.arm()
        val c = p.commit("10.0.0.2", 1, "edith".toByteArray(), key)!!
        val (k, n) = p.reveal("10.0.0.2", 1, nh)!!
        assertArrayEquals(key, k)
        assertArrayEquals(Pairing.commitment(k, n), c)
        assertEquals(PairingSession.State.CODE, p.view().state)
        assertEquals(Pairing.code(k, n, nh), p.view().code)
        assertEquals(true, p.done("10.0.0.2", nh))
        assertEquals(PairingSession.State.DONE, p.view().state)
    }

    @Test
    fun `nothing is accepted unless the user armed pairing`() {
        assertNull(session().commit("10.0.0.2", 1, ByteArray(0), key))
    }

    @Test
    fun `one exchange per arming - the grinding attack gets one try`() {
        // Someone in the middle who knows the code the COMPUTER expects would repeat pairing
        // with fresh phone nonces until the phone shows that code. The second commit must not
        // produce a new code; it must stop the pairing visibly.
        val p = session()
        p.arm()
        p.commit("10.0.0.66", 1, ByteArray(0), key)!!
        p.reveal("10.0.0.66", 1, nh)!!
        assertNull(p.commit("10.0.0.66", 2, ByteArray(0), key))
        assertEquals(PairingSession.State.INTERRUPTED, p.view().state)
        assertNull("no code survives an interruption", p.view().code)
        assertNull("and nothing more is accepted", p.commit("10.0.0.66", 3, ByteArray(0), key))
    }

    @Test
    fun `a second computer committing mid-pairing interrupts it`() {
        val p = session()
        p.arm()
        p.commit("10.0.0.2", 1, ByteArray(0), key)!!
        assertNull(p.commit("10.0.0.66", 9, ByteArray(0), key))
        assertEquals(PairingSession.State.INTERRUPTED, p.view().state)
    }

    @Test
    fun `reveal must come on the committing connection, once, with a full nonce`() {
        val p = session()
        p.arm()
        p.commit("10.0.0.2", 1, ByteArray(0), key)!!
        assertNull("short nonce", p.reveal("10.0.0.2", 1, ByteArray(8)))
        assertNotNull(p.reveal("10.0.0.2", 1, nh))
        assertNull("only once", p.reveal("10.0.0.2", 1, nh))

        val q = session()
        q.arm()
        q.commit("10.0.0.2", 1, ByteArray(0), key)!!
        assertNull(q.reveal("10.0.0.2", 2, nh))
        assertEquals(PairingSession.State.INTERRUPTED, q.view().state)
    }

    @Test
    fun `done only counts for this pairing`() {
        val p = session()
        p.arm()
        p.commit("10.0.0.2", 1, ByteArray(0), key)!!
        p.reveal("10.0.0.2", 1, nh)!!
        assertEquals(false, p.done("10.0.0.66", nh))
        assertEquals(false, p.done("10.0.0.2", ByteArray(32)))
        assertEquals(PairingSession.State.CODE, p.view().state)
    }

    @Test
    fun `an armed pairing expires`() {
        val p = session()
        p.arm()
        p.commit("10.0.0.2", 1, ByteArray(0), key)!!
        t += Pairing.CODE_TTL_MS
        assertEquals(PairingSession.State.EXPIRED, p.view().state)
        assertNull(p.reveal("10.0.0.2", 1, nh))
    }

    @Test
    fun `cancelling disarms`() {
        val p = session()
        p.arm()
        p.disarm()
        assertNull(p.commit("10.0.0.2", 1, ByteArray(0), key))
        assertEquals(PairingSession.State.IDLE, p.view().state)
    }
}
