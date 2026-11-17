package com.ritwick.sudostamp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pairing by QR code (qr-v1): the derivations (byte for byte with tools/pair.py), the link the
 * code holds, and the phone's state machine -- above all that nothing without the secret has
 * any effect, and that the two pairing modes never mix.
 */
class QrPairingTest {

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    // The vectors of PairingTest, plus the secret: produced by tools/pair.py (test_pair.py).
    private val key = hex(
        "0000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041" +
            "040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
            "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
    )
    private val np = ByteArray(32) { it.toByte() }
    private val nh = ByteArray(32) { (it + 32).toByte() }
    private val dialled = hex("00000000000000000000ffffc0a801141e61")
    private val stable = hex("fd6c5c9300231f7e445b9bfffe36628a1e61")
    private val secret = ByteArray(16) { (it + 100).toByte() }

    @Test
    fun `the derivations match the Python implementation`() {
        assertArrayEquals(hex("31f4cea57d62d633c97c53e9d334977711d78786b42dd0284f6e366000e1a4e4"), Pairing.qrHello(secret))
        assertArrayEquals(hex("3bf5b2c6b26a47adacf03c1bad1e01e5b44e8e307eeffaa47903663fbf56aad9"), Pairing.qrCommitMac(secret, nh, dialled))
        assertArrayEquals(hex("8cb878e9ec27f7b7464167117bff19f3cbaf37d163177cb0514d16094217bd9b"),
            Pairing.qrPhoneMac(secret, nh, key, np, dialled, stable))
        assertArrayEquals(hex("85497f963bbac992724f61dc216216d337c3bf7d00a0a27b2367e99e0229f2d9"), Pairing.qrDoneMac(secret, nh, key))
    }

    @Test
    fun `each proof is bound to its own role and inputs`() {
        val other = secret.copyOf().also { it[0] = 1 }
        assertFalse(Pairing.same(Pairing.qrCommitMac(secret, nh, dialled), Pairing.qrCommitMac(other, nh, dialled)))
        assertFalse(Pairing.same(Pairing.qrCommitMac(secret, nh, dialled), Pairing.qrCommitMac(secret, nh, stable)))
        assertFalse("a done proof is not a commit proof",
            Pairing.same(Pairing.qrDoneMac(secret, nh, dialled), Pairing.qrCommitMac(secret, nh, dialled)))
        assertFalse(Pairing.same(null, ByteArray(32)))
        assertFalse(Pairing.same(ByteArray(31), ByteArray(32)))
    }

    // ------------------------------------------------------------------- the link

    @Test
    fun `a link reads back what the computer put in it`() {
        val url = QrLink.build(secret, "edith")
        assertEquals("https://sudostamp.ritwickverma.dev/pair#1.ZGVmZ2hpamtsbW5vcHFycw.ZWRpdGg", url)
        val l = parse(url)!!
        assertArrayEquals(secret, l.secret)
        assertEquals("edith", l.label)
        assertNotNull("trailing slash", QrLink.parse("https", QrLink.HOST, "/pair/", "1.ZGVmZ2hpamtsbW5vcHFycw.ZWRpdGg"))
        assertEquals("no name", "a computer", QrLink.parse("https", QrLink.HOST, "/pair", "1.ZGVmZ2hpamtsbW5vcHFycw.")!!.label)
    }

    @Test
    fun `anything else is no link at all`() {
        val f = "1.ZGVmZ2hpamtsbW5vcHFycw.ZWRpdGg"
        for ((scheme, host, path, frag) in listOf(
            listOf("http", QrLink.HOST, "/pair", f),
            listOf("https", "ritwickverma.dev", "/pair", f),
            listOf("https", "evil.example", "/pair", f),
            listOf("https", QrLink.HOST.uppercase(), "/pair", f),
            listOf("https", QrLink.HOST, "/pairx", f),
            listOf("https", QrLink.HOST, "/", f),
            listOf("https", QrLink.HOST, "/pair", null),
            listOf("https", QrLink.HOST, "/pair", ""),
            listOf("https", QrLink.HOST, "/pair", "2.ZGVmZ2hpamtsbW5vcHFycw.ZWRpdGg"),
            listOf("https", QrLink.HOST, "/pair", "1.ZGVmZ2hpamtsbW5vcHFycw"),
            listOf("https", QrLink.HOST, "/pair", "1.ZGVmZ2hpamtsbW5vcHFycw.ZWRpdGg.x"),
            listOf("https", QrLink.HOST, "/pair", "1.ZGVmZ2hpamtsbW5vcHFyc.ZWRpdGg"),        // 15 bytes and a bit
            listOf("https", QrLink.HOST, "/pair", "1.ZGVmZ2hpamtsbW5vcHFycwAA.ZWRpdGg"),         // 17 bytes
            listOf("https", QrLink.HOST, "/pair", "1.ZGVmZ2hpamtsbW5vcHFyct.ZWRpdGg"),        // non-canonical last char
            listOf("https", QrLink.HOST, "/pair", "1.ZGVmZ2hpamtsbW5vcHFycw==.ZWRpdGg"),          // padding
            listOf("https", QrLink.HOST, "/pair", "1.+GVmZ2hpamtsbW5vcHFycw.ZWRpdGg"), // not url-safe
            listOf("https", QrLink.HOST, "/pair", "1.ZGVmZ2hpamtsbW5vcHFycw." + "QUFB".repeat(11)),      // 33-byte name
        )) {
            assertNull("$scheme://$host$path#$frag", QrLink.parse(scheme, host, path, frag))
        }
    }

    @Test
    fun `from the pairing page's button the code comes as k, never both ways`() {
        val f = "1.ZGVmZ2hpamtsbW5vcHFycw.ZWRpdGg"
        assertArrayEquals(secret, QrLink.parse("https", QrLink.HOST, "/pair", null, f)!!.secret)
        assertNull(QrLink.parse("https", QrLink.HOST, "/pair", f, f))
        assertNull(QrLink.parse("https", QrLink.HOST, "/pair", null, "2.x.y"))
    }

    @Test
    fun `the name is display text only`() {
        val l = QrLink.parse("https", QrLink.HOST, "/pair", "1.ZGVmZ2hpamtsbW5vcHFycw." +
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("a\u0007b\nc".toByteArray()))!!
        assertEquals("abc", l.label)
    }

    private fun parse(url: String): QrLink.Link? {
        val u = java.net.URI(url)
        return QrLink.parse(u.scheme, u.host, u.path, u.fragment)
    }

    // ------------------------------------------------------------- state machine

    private var t = 0L
    private var made = 0
    private fun session() = PairingSession({ t }, { n -> ByteArray(n) { it.toByte() } })
    private val newKey = { _: ByteArray -> PairingSession.NewKey("%016x".format(++made), key) }
    private fun PairingSession.go(client: String = "10.0.0.2", conn: Long = 1, s: ByteArray = secret, at: ByteArray = dialled) =
        qrCommit(client, conn, nh, Pairing.qrCommitMac(s, nh, at), dialled, stable, newKey)
    private fun PairingSession.finish(client: String = "10.0.0.2", conn: Long = 1, s: ByteArray = secret) =
        qrDone(client, conn, nh, Pairing.qrDoneMac(s, nh, key))
    private fun armed() = session().apply { armQr(secret, "edith") }

    @Test
    fun `one honest pairing runs hello, commit, done, attestation`() {
        val p = armed()
        assertEquals("edith", p.view().label)
        assertTrue(p.view().qr)
        assertTrue(p.discoverable())
        assertTrue(p.qrHello(Pairing.qrHello(secret)))
        val r = p.go()!!
        assertArrayEquals(key, r.keyBlob)
        assertArrayEquals(dialled, r.dialled)
        assertArrayEquals(stable, r.stable)
        assertArrayEquals(Pairing.qrPhoneMac(secret, nh, key, r.phoneNonce, dialled, stable), r.mac)
        assertFalse("found: no longer discoverable", p.discoverable())
        assertFalse("nor says yes to hello", p.qrHello(Pairing.qrHello(secret)))
        assertEquals("0000000000000001", p.finish())
        assertEquals(PairingSession.State.DONE, p.view().state)
        assertEquals("edith", p.view().label)
        p.disarm()
        assertEquals(emptyList<String>(), p.drainDiscarded())
    }

    @Test
    fun `without the secret nothing has any effect`() {
        val p = armed()
        val wrong = secret.copyOf().also { it[15] = 0 }
        assertFalse(p.qrHello(Pairing.qrHello(wrong)))
        assertFalse(p.qrHello(ByteArray(0)))
        assertNull(p.go(s = wrong))
        assertNull(p.qrCommit("10.0.0.66", 1, nh, ByteArray(32), dialled, stable, newKey))
        assertNull(p.qrCommit("10.0.0.66", 1, nh, ByteArray(0), dialled, stable, newKey))
        assertEquals("no key made", 0, made)
        assertEquals("still waiting", PairingSession.State.WAITING, p.view().state)
        p.go()!!
        assertNull("a forged done", p.qrDone("10.0.0.2", 1, nh, ByteArray(32)))
        assertNull(p.finish(s = wrong))
        assertNull(p.go(s = wrong))
        assertEquals("forgeries never interrupt", PairingSession.State.COMMITTED, p.view().state)
        assertNotNull(p.finish())
    }

    @Test
    fun `a relay is refused - the proof covers where the phone was dialled`() {
        // The computer dialled a relay at 10.0.0.99 and proved the secret over THAT; the phone
        // checks it against where it was dialled.
        val relay = hex("00000000000000000000ffff0a0000631e61")
        val p = armed()
        assertNull(p.go(at = relay))
        assertEquals(PairingSession.State.WAITING, p.view().state)
        assertEquals(0, made)
    }

    @Test
    fun `a second holder of the secret stops the pairing and its key goes`() {
        val p = armed()
        p.go()!!
        assertNull(p.go(client = "10.0.0.66", conn = 9))
        assertEquals(PairingSession.State.INTERRUPTED, p.view().state)
        assertEquals(listOf("0000000000000001"), p.drainDiscarded())
        assertNull("and the secret is gone with it", p.go(conn = 10))

        val q = armed()
        q.go()!!; q.finish()!!
        assertNull(q.go(client = "10.0.0.66", conn = 9))
        assertEquals("even a finished one, inside the arming", PairingSession.State.INTERRUPTED, q.view().state)
        assertEquals(listOf("0000000000000002"), q.drainDiscarded())
    }

    @Test
    fun `done comes on the commit's connection, for its nonce`() {
        val p = armed()
        p.go()!!
        assertNull(p.finish(conn = 2))
        assertNull(p.finish(client = "10.0.0.3"))
        assertNull(p.qrDone("10.0.0.2", 1, ByteArray(32), Pairing.qrDoneMac(secret, ByteArray(32), key)))
        assertNotNull(p.finish())
        assertNull("once", p.finish())
    }

    @Test
    fun `the modes never mix`() {
        val p = armed()
        assertNull("a code-mode commit", p.commit("10.0.0.66", 1, "x".toByteArray(), dialled, stable, newKey))
        assertNull(p.reveal("10.0.0.66", 1, nh))
        assertNull(p.done("10.0.0.66", nh))
        p.olderProtocol("10.0.0.66")
        assertEquals(PairingSession.State.WAITING, p.view().state)
        p.go()!!
        assertNull(p.reveal("10.0.0.66", 1, nh))
        assertEquals("a code-mode reveal does not interrupt a QR pairing", PairingSession.State.COMMITTED, p.view().state)
        assertEquals(1, made)

        val c = session().apply { arm() }
        assertFalse(c.qrHello(Pairing.qrHello(secret)))
        assertNull(c.go())
        assertFalse(c.view().qr)
        assertEquals(PairingSession.State.WAITING, c.view().state)
    }

    @Test
    fun `the secret ends with the arming`() {
        val p = armed()
        t += Pairing.CODE_TTL_MS
        assertEquals(PairingSession.State.EXPIRED, p.view().state)
        assertNull(p.go())
        val q = armed()
        q.disarm()
        assertNull(q.go())
        q.arm()
        assertFalse("re-armed for a code, the old secret is gone", q.qrHello(Pairing.qrHello(secret)))
        val r = armed()
        r.go()!!
        t += Pairing.CODE_TTL_MS
        assertNull(r.finish())
        assertEquals("an unfinished pairing's key goes when it expires", listOf("0000000000000001"), r.drainDiscarded())
    }

    @Test
    fun `the attestation goes to the computer that paired, after done`() {
        val withAtt = { c: ByteArray -> PairingSession.NewKey("k", key, PairingSession.Attestation(c, listOf(byteArrayOf(1)))) }
        val p = armed()
        p.qrCommit("10.0.0.2", 1, nh, Pairing.qrCommitMac(secret, nh, dialled), dialled, stable, withAtt)!!
        assertNull(p.attestation("10.0.0.2"))
        p.finish()!!
        assertNull(p.attestation("10.0.0.3"))
        assertNotNull(p.attestation("10.0.0.2"))
    }

    @Test
    fun `malformed lengths are refused before anything`() {
        val p = armed()
        assertNull(p.qrCommit("10.0.0.2", 1, ByteArray(31), Pairing.qrCommitMac(secret, ByteArray(31), dialled), dialled, stable, newKey))
        assertNull(p.qrCommit("10.0.0.2", 1, nh, Pairing.qrCommitMac(secret, nh, ByteArray(4)), ByteArray(4), stable, newKey))
        assertEquals(0, made)
        assertEquals(PairingSession.State.WAITING, p.view().state)
    }
}
