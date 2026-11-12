package com.ritwick.sudostamp

import com.ritwick.sudostamp.PairingSession.State
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

/**
 * The pairing messages come off the network (the computer's label, its nonce, its endpoints) and
 * drive a state machine on the phone. Properties:
 *
 *  - the label is display text whatever bytes arrive;
 *  - the commitment and the code cover every field, framed so no two splits of the same bytes
 *    agree, and the code is always six digits;
 *  - PairingSession, driven by random sequences of every call from two computers over three
 *    connections with a clock that jumps, behaves as the one-attempt-per-arming machine in its
 *    class comment: each step succeeds exactly when the model says it may, one commit per
 *    arming, and every key it makes is either handed back for deletion or kept by a finished
 *    pairing, never forgotten.
 */
class PairingFuzzTest {

    // ------------------------------------------------------------------ label

    @Test
    fun `cleanLabel is printable ASCII, at most 64 characters, never empty, for any bytes`() {
        Fuzz.run("pairing/label", 31) { _, r ->
            val raw = when (r.nextInt(4)) {
                0 -> Fuzz.bytes(r, r.nextInt(200))
                1 -> ByteArray(r.nextInt(300)) { (0x20 + r.nextInt(0x5F)).toByte() }                       // all printable, maybe long
                2 -> ByteArray(r.nextInt(40)) { listOf(0, 7, 10, 13, 27, 0x7F, 0x80, 0xFF, 0x20, 0x41)[r.nextInt(10)].toByte() }
                else -> ByteArray(r.nextInt(5000)) { 0x20 }
            }
            val s = Pairing.cleanLabel(raw)
            assertTrue("empty", s.isNotEmpty())
            assertTrue("${s.length} characters", s.length <= 64)
            assertTrue("not printable ASCII: ${s.map { it.code }}", s.all { it in ' '..'~' })
            // What is printable survives, in order (it is a filter and a trim, not a rewrite).
            val kept = String(raw, Charsets.US_ASCII).filter { it in ' '..'~' }.trim().take(64)
            assertEquals(kept.ifEmpty { "a computer" }, s)
        }
    }

    // ------------------------------------------------------------------ commitment and code

    private fun flip(b: ByteArray, r: Random): ByteArray = b.copyOf().also {
        if (it.isNotEmpty()) { val at = r.nextInt(it.size); it[at] = (it[at].toInt() xor (1 shl r.nextInt(8))).toByte() }
    }

    @Test
    fun `commitment and code cover every field, are framed, and the code is six digits`() {
        Fuzz.run("pairing/hash", 32, weight = 50) { _, r ->
            val parts = listOf(Fuzz.bytes(r, 1 + r.nextInt(104)), Fuzz.bytes(r, 32), Fuzz.bytes(r, 18), Fuzz.bytes(r, 18))
            val nh = Fuzz.bytes(r, 32)
            val c = Pairing.commitment(parts[0], parts[1], parts[2], parts[3])
            assertArrayEquals("deterministic", c, Pairing.commitment(parts[0], parts[1], parts[2], parts[3]))
            val code = Pairing.code(parts[0], parts[1], nh, parts[2], parts[3])
            assertTrue(code, code.matches(Regex("[0-9]{6}")))
            assertEquals(code, Pairing.code(parts[0], parts[1], nh, parts[2], parts[3]))
            assertTrue(Pairing.spaced(code).matches(Regex("[0-9]{3} [0-9]{3}")))

            // One flipped bit in any one field: a different commitment. (A field the hash forgot
            // would make an impostor free to choose it.)
            val k = r.nextInt(4)
            val changed = parts.toMutableList().also { it[k] = flip(it[k], r) }
            assertFalse("commitment ignores field $k", c.contentEquals(Pairing.commitment(changed[0], changed[1], changed[2], changed[3])))

            // The same bytes cut elsewhere are a different message: a byte moved from one field to
            // its neighbour must change the hash, or two different pairings could share a code.
            val a = r.nextInt(3)
            if (parts[a].size > 1) {
                val moved = parts.toMutableList()
                moved[a] = parts[a].copyOfRange(0, parts[a].size - 1)
                moved[a + 1] = byteArrayOf(parts[a].last()) + parts[a + 1]
                assertFalse("commitment is not length-framed at $a", c.contentEquals(Pairing.commitment(moved[0], moved[1], moved[2], moved[3])))
            }
            // The code binds the host's nonce too. Six digits can collide by chance (one in a
            // million), so ask for one different code out of six fresh nonces, not for inequality.
            val others = (0 until 6).map { Pairing.code(parts[0], parts[1], Fuzz.bytes(r, 32), parts[2], parts[3]) }
            assertTrue("the code ignores the host nonce: $code $others", others.any { it != code })
        }
    }

    // ------------------------------------------------------------------ the state machine

    private enum class Stage { NONE, COMMITTED, REVEALED, DONE }

    private class Key(val id: String, val blob: ByteArray)

    @Test
    fun `random call sequences follow the one attempt per arming machine and leak no key`() {
        Fuzz.run("pairing/session", 33, weight = 5) { _, r ->
            var clock = 1_000_000L
            val rng = Random(r.nextLong())
            val s = PairingSession(now = { clock }, random = { n -> Fuzz.bytes(rng, n) })

            val created = LinkedHashMap<String, Key>()
            val drained = ArrayList<String>()
            val finished = HashSet<String>()
            var counter = 0

            // The model.
            var waiting = false
            var deadline = 0L
            var stage = Stage.NONE
            var client = ""
            var conn = -1L
            var key: Key? = null
            var commitment: ByteArray? = null
            var nh: ByteArray? = null
            var commitsThisArming = 0
            val clients = listOf("10.0.0.1", "10.0.0.2")

            fun expireModel() {
                if (clock >= deadline) {
                    if (waiting) waiting = false
                    if (stage == Stage.COMMITTED || stage == Stage.REVEALED) stage = Stage.NONE
                }
            }
            fun drain() { drained += s.drainDiscarded() }

            repeat(40 + r.nextInt(60)) {
                when (r.nextInt(10)) {
                    0 -> { s.arm(); waiting = true; deadline = clock + Pairing.CODE_TTL_MS; stage = Stage.NONE; commitsThisArming = 0 }
                    1 -> if (r.nextInt(3) == 0) { s.disarm(); waiting = false; stage = Stage.NONE }
                    2, 3 -> {
                        val from = clients[r.nextInt(2)]
                        val c = 1L + r.nextInt(3)
                        val okSizes = r.nextInt(6) != 0
                        val dialled = Fuzz.bytes(rng, if (okSizes) 18 else listOf(0, 17, 19, 32)[r.nextInt(4)])
                        val stable = Fuzz.bytes(rng, if (okSizes || r.nextBoolean()) 18 else 16)
                        val keyFails = r.nextInt(8) == 0
                        var made: Key? = null
                        var called = 0
                        expireModel()
                        val may = waiting && clock < deadline && dialled.size == 18 && stable.size == 18 && !keyFails
                        val mayInterrupt = !waiting && (stage == Stage.COMMITTED || stage == Stage.REVEALED || (stage == Stage.DONE && clock < deadline))
                        val out = s.commit(from, c, Fuzz.bytes(rng, r.nextInt(100)), dialled, stable) {
                            called++
                            if (keyFails) null
                            else Key("k${counter++}", Fuzz.bytes(rng, 104)).also { made = it; created[it.id] = it }.let { PairingSession.NewKey(it.id, it.blob) }
                        }
                        if (dialled.size != 18 || stable.size != 18) assertEquals("no key may be made for a malformed endpoint", 0, called)
                        assertEquals("commit succeeds exactly when waiting, in time, well-formed", may, out != null)
                        if (out != null) {
                            assertEquals(32, out.size)
                            commitsThisArming++
                            assertEquals("a second exchange per arming", 1, commitsThisArming)
                            waiting = false; stage = Stage.COMMITTED; client = from; conn = c; key = made; commitment = out; nh = null
                        } else if (mayInterrupt) {
                            stage = Stage.NONE
                            assertEquals("a second computer cancels", State.INTERRUPTED, s.view().state)
                        } else if (made != null) {
                            throw AssertionError("a key was made for a commit that was refused")
                        }
                    }
                    4, 5 -> {
                        // Mostly the computer that committed, on its own connection; sometimes not.
                        val own = stage != Stage.NONE && r.nextInt(5) != 0
                        val from = if (own) client else clients[r.nextInt(2)]
                        val c = if (own) conn else 1L + r.nextInt(3)
                        val good = r.nextInt(6) != 0
                        val n = Fuzz.bytes(rng, if (good) 32 else listOf(0, 31, 33, 64)[r.nextInt(4)])
                        expireModel()
                        val inTime = clock < deadline
                        val committed = stage == Stage.COMMITTED && inTime
                        val matches = from == client && c == conn
                        val rev = s.reveal(from, c, n)
                        assertEquals("reveal succeeds exactly for the committer, on its connection, with a 32 byte nonce, in time",
                            committed && matches && n.size == 32, rev != null)
                        if (rev != null) {
                            stage = Stage.REVEALED; nh = n
                            assertArrayEquals(key!!.blob, rev.keyBlob)
                            assertEquals(32, rev.phoneNonce.size); assertEquals(18, rev.dialled.size); assertEquals(18, rev.stable.size)
                            assertArrayEquals("the reveal opens the commitment", commitment, Pairing.commitment(rev.keyBlob, rev.phoneNonce, rev.dialled, rev.stable))
                            val v = s.view()
                            assertEquals(State.CODE, v.state)
                            assertEquals(Pairing.code(rev.keyBlob, rev.phoneNonce, n, rev.dialled, rev.stable), v.code)
                        } else if (committed && !matches) {
                            stage = Stage.NONE
                            assertEquals(State.INTERRUPTED, s.view().state)
                        }
                    }
                    6, 7 -> {
                        val own = stage != Stage.NONE && r.nextInt(5) != 0
                        val from = if (own) client else clients[r.nextInt(2)]
                        val n = if (own && nh != null && r.nextInt(5) != 0) nh!!.copyOf() else Fuzz.bytes(rng, 32)
                        expireModel()
                        val may = stage == Stage.REVEALED && clock < deadline && from == client && n.contentEquals(nh)
                        val id = s.done(from, n)
                        assertEquals("done succeeds exactly for the committer with the revealed nonce, once", may, id != null)
                        if (id != null) { assertEquals(key!!.id, id); finished += id; stage = Stage.DONE }
                    }
                    8 -> {
                        val from = clients[r.nextInt(2)]
                        expireModel()
                        val may = waiting && clock < deadline
                        s.olderProtocol(from)
                        if (may) { waiting = false; assertEquals(State.OUTDATED, s.view().state) }
                    }
                    else -> {
                        clock += when (r.nextInt(4)) { 0 -> 0L; 1 -> 1L + r.nextInt(1000); 2 -> Pairing.CODE_TTL_MS - 1 + r.nextInt(3); else -> r.nextInt(3 * Pairing.CODE_TTL_MS.toInt()).toLong() }
                    }
                }
                // After every step: what the screen may show.
                expireModel()
                val v = s.view()
                // DONE keeps showing it (the person has just typed it); no other state may.
                if (v.state != State.CODE && v.state != State.DONE) assertNull("the code is shown only in CODE or DONE", v.code)
                else assertTrue(v.code!!.matches(Regex("[0-9]{6}")))
                v.label?.let { assertTrue(it.length <= 64 && it.all { c -> c in ' '..'~' }) }
                assertEquals("discoverable only while nobody has committed", s.discoverable(), v.state == State.WAITING)
                if (r.nextInt(4) == 0) drain()
            }

            // Everything made is accounted for: handed back once for deletion, or kept by a finished pairing.
            clock += 10 * Pairing.CODE_TTL_MS
            s.view()
            drain()
            assertEquals("a key was handed back for deletion twice: $drained", drained.size, drained.toSet().size)
            assertTrue("handed back a key it never made", created.keys.containsAll(drained))
            val forgotten = created.keys - drained.toSet() - finished
            assertTrue("keys neither deleted nor kept: $forgotten", forgotten.isEmpty())
        }
    }

    // ------------------------------------------------------------------ a few named cases the fuzz leans on

    @Test
    fun `a finished pairing is cancelled by a second commit inside the window and its key handed back`() {
        var clock = 0L
        val s = PairingSession(now = { clock }, random = { n -> ByteArray(n) { 7 } })
        s.arm()
        val ep = ByteArray(18)
        val c = s.commit("a", 1, "pc".toByteArray(), ep, ep) { PairingSession.NewKey("k0", ByteArray(104)) }
        assertNotNull(c)
        val rev = s.reveal("a", 1, ByteArray(32))
        assertNotNull(rev)
        assertEquals("k0", s.done("a", ByteArray(32)))
        assertNull(s.commit("b", 2, "evil".toByteArray(), ep, ep) { PairingSession.NewKey("k1", ByteArray(104)) })
        assertEquals(State.INTERRUPTED, s.view().state)
        assertEquals(listOf("k0"), s.drainDiscarded())
        assertNotEquals(State.WAITING, s.view().state)
    }
}
