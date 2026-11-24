package com.ritwick.sudostamp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Pairing v3 (2.0): the computer's host key H, carried by the reveal (code mode) or the commit
 * (QR mode), covered by the code or the computer's MAC, and recorded with the computer. Vectors
 * from tools/pair.py; tools/test/test_fuzz_pair.py runs pair.py against a phone that swaps H.
 */
class PairingV3Test {

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private val key = hex(
        "0000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041" +
            "040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
            "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
    )
    private val np = ByteArray(32) { it.toByte() }
    private val nh = ByteArray(32) { (it + 32).toByte() }
    private val dialled = hex("00000000000000000000ffffc0a801141e61")
    private val stable = hex("fd6c5c9300231f7e445b9bfffe36628a1e61")
    private val h = hex("04b80a6328f448a8796d12339d9c16f4f7c057ba2c7684b396f55b7b95ae6d933c4e308f4b1237f4d7d3798f8c1a834debefacfb70c020e5b2c970916b667e85a8")
    private val h2 = hex("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0")

    @Test
    fun `v3 code and QR commit MAC match the Python implementation`() {
        assertEquals("397004", Pairing.code(key, np, nh, dialled, stable))            // v2, unchanged
        assertEquals("920289", Pairing.code(key, np, nh, dialled, stable, h))
        assertEquals("191486", Pairing.code(key, np, nh, dialled, stable, h2))
        val secret = ByteArray(16) { it.toByte() }
        val nc = ByteArray(32) { (it + 64).toByte() }
        assertArrayEquals(hex("e4c0b26b4f0260f10df7cac408828976270f8dea423e3b0c631885b3e270fe03"),
            Pairing.qrCommitMac(secret, nh, nc, dialled))
        assertArrayEquals(hex("f008f70e959b1f8e54fa1f86694ff7af663eadb463d30dd52c46684581ae4ff4"),
            Pairing.qrCommitMacV3(secret, nh, nc, dialled, h))
    }

    // ------------------------------------------------------------- code mode

    private var t = 0L
    private var made = 0
    private fun session() = PairingSession({ t }, { n -> ByteArray(n) { it.toByte() } })
    private val newKey = { _: ByteArray -> PairingSession.NewKey("%016x".format(++made), key) }
    private fun committed() = session().apply {
        arm()
        commit("10.0.0.2", 1, "edith".toByteArray(), dialled, stable, newKey)!!
    }

    @Test
    fun `the code covers H - a substituted host key shows another code`() {
        val p = committed()
        val v = p.reveal("10.0.0.2", 1, nh, h)!!
        assertEquals(Pairing.code(v.keyBlob, v.phoneNonce, nh, dialled, stable, h), p.view().code)
        assertNotEquals(Pairing.code(v.keyBlob, v.phoneNonce, nh, dialled, stable, h2), p.view().code)
        assertNotEquals("v3 is not v2", Pairing.code(v.keyBlob, v.phoneNonce, nh, dialled, stable), p.view().code)
    }

    @Test
    fun `H is recorded only once the pairing is done`() {
        val p = committed()
        p.reveal("10.0.0.2", 1, nh, h)!!
        assertNull("not before done", p.doneHostKey())
        assertEquals("0000000000000001", p.done("10.0.0.2", nh))
        assertNull("not before the person confirms", p.doneHostKey())
        assertArrayEquals(h, p.confirm()!!.hostKey)
        assertArrayEquals(h, p.doneHostKey())
        p.disarm()
        assertNull("not after the screen closed", p.doneHostKey())
    }

    @Test
    fun `a v2 reveal records no host key`() {
        val p = committed()
        p.reveal("10.0.0.2", 1, nh)!!
        p.done("10.0.0.2", nh)!!
        assertNull(p.confirm()!!.hostKey)
    }

    @Test
    fun `a host key that is not a P-256 point stops the pairing and its key goes`() {
        for (bad in listOf(ByteArray(0), h.copyOf(64), h.copyOf().also { it[64] = (it[64].toInt() xor 1).toByte() },
                byteArrayOf(2) + h.copyOfRange(1, 33))) {
            val p = committed()
            assertNull(p.reveal("10.0.0.2", 1, nh, bad))
            assertEquals(PairingSession.State.INTERRUPTED, p.view().state)
            assertEquals(1, p.drainDiscarded().size)
            assertNull("no v2 reveal after it either", p.reveal("10.0.0.2", 1, nh))
        }
    }

    // ------------------------------------------------------------- QR mode

    private val secret = ByteArray(16) { (it + 100).toByte() }
    private val nq = ByteArray(32) { (it + 128).toByte() }
    private fun qrArmed() = session().apply { armQr(secret, "edith") }
    private fun PairingSession.helloNonce(conn: Long) = qrHello(conn, Pairing.qrHello(secret), nq)!!.connNonce

    @Test
    fun `QR commit v2 carries H under the computer's MAC`() {
        val p = qrArmed()
        val nc = p.helloNonce(1)
        p.qrCommit("10.0.0.2", 1, nh, Pairing.qrCommitMacV3(secret, nh, nc, dialled, h), dialled, stable, newKey, h)!!
        p.qrDone("10.0.0.2", 1, nh, Pairing.qrDoneMac(secret, nh, key))!!
        assertArrayEquals(h, p.doneHostKey())
    }

    @Test
    fun `a swapped H fails the MAC, and spends the connection's nonce`() {
        val p = qrArmed()
        val nc = p.helloNonce(1)
        assertNull(p.qrCommit("10.0.0.2", 1, nh, Pairing.qrCommitMacV3(secret, nh, nc, dialled, h), dialled, stable, newKey, h2))
        assertEquals("nothing was made", 0, made)
        // The v1 commit the computer would fall back to finds no nonce on this connection.
        assertNull(p.qrCommit("10.0.0.2", 1, nh, Pairing.qrCommitMac(secret, nh, nc, dialled), dialled, stable, newKey))
        // A v1 MAC presented as v2 (H stripped from what the MAC covers) is refused too.
        val nc2 = p.helloNonce(2)
        assertNull(p.qrCommit("10.0.0.2", 2, nh, Pairing.qrCommitMac(secret, nh, nc2, dialled), dialled, stable, newKey, h))
        assertEquals(PairingSession.State.WAITING, p.view().state)
    }

    @Test
    fun `a malformed H in a QR commit is refused before a key is made`() {
        val p = qrArmed()
        val bad = h.copyOf(64)
        val nc = p.helloNonce(1)
        assertNull(p.qrCommit("10.0.0.2", 1, nh, Pairing.qrCommitMacV3(secret, nh, nc, dialled, bad), dialled, stable, newKey, bad))
        assertEquals(0, made)
    }

    // ------------------------------------------------------------- Hosts

    @Test
    fun `hosts keep H across encode and decode, and rows from before 2_0 still read`() {
        val b64 = java.util.Base64.getEncoder().encodeToString(h)
        val with = Host("0123456789abcdef", "edith", 1L, true, "10.0.0.2", b64)
        val without = Host("fedcba9876543210", "old", 2L, false, "10.0.0.3")
        val back = Hosts.decode(Hosts.encode(listOf(with, without)))
        assertEquals(listOf(with, without), back)
        assertArrayEquals(h, back[0].hostKeyBytes())
        assertNull(back[1].hostKeyBytes())
        // A 1.x row (five fields) reads; a damaged host key means no secrets, not no computer.
        val old = "fedcba9876543210\t2\t0\t${java.util.Base64.getEncoder().encodeToString("old".toByteArray())}\t" +
            java.util.Base64.getEncoder().encodeToString("10.0.0.3".toByteArray())
        assertEquals(listOf(without), Hosts.decode(old))
        val damaged = Hosts.decode(old + "\t" + java.util.Base64.getEncoder().encodeToString(h.copyOf(64)))
        assertEquals(1, damaged.size)
        assertNull(damaged[0].hostKeyBytes())
        assertNull(Hosts.decode("$old\tnot base64!").single().hostKeyBytes())
    }
}
