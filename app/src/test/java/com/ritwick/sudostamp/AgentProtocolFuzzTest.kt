package com.ritwick.sudostamp

import com.ritwick.sudostamp.Fuzz.LIES
import com.ritwick.sudostamp.Fuzz.str
import com.ritwick.sudostamp.Fuzz.u32
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.lang.management.ManagementFactory
import java.util.Random

/**
 * Everything a LAN peer can put on the wire reaches AgentProtocol first, so this is the parser
 * of untrusted bytes. Properties, checked over seeded random input and over valid frames
 * mutated the ways a hostile client would (truncation, length-field lies, nested blob lies,
 * type-byte sweep, trailing garbage):
 *
 *  - readFrame returns null, a frame, or throws IOException; nothing else, ever;
 *  - it is exactly the reference parser below (a differential test), and it never reads past, or
 *    allocates for, a length prefix outside 1..64 KiB;
 *  - Reader fails only with EOFException, and agrees with a reference that uses Long arithmetic;
 *  - refusal() answers "may be put to the user" (null) for one input only: a known key and
 *    exactly 32 bytes.
 *
 * The request loop itself (AgentService.serve) needs Android; [decodeSign] repeats its reading
 * sequence (skipType, blob, blob, int32) so the same bytes can be run through it here.
 */
class AgentProtocolFuzzTest {

    private val MAX_FRAME = 64 * 1024

    // ------------------------------------------------------------------ corpus + mutators

    private fun keyBlob(r: Random): ByteArray =
        str("ecdsa-sha2-nistp256") + str("nistp256") + str(byteArrayOf(4) + Fuzz.bytes(r, 64))

    private fun frame(body: ByteArray): ByteArray = u32(body.size) + body

    private fun signBody(key: ByteArray, data: ByteArray, flags: Int): ByteArray =
        byteArrayOf(AgentProtocol.SSH2_AGENTC_SIGN_REQUEST.toByte()) + str(key) + str(data) + u32(flags)

    private fun extBody(name: String, vararg parts: ByteArray): ByteArray =
        byteArrayOf(AgentProtocol.SSH2_AGENTC_EXTENSION.toByte()) + str(name) +
            parts.fold(ByteArray(0)) { acc, p -> acc + str(p) }

    /** A well-formed request frame of a random kind: what the mutators start from. */
    private fun validFrame(r: Random): ByteArray = frame(when (r.nextInt(7)) {
        0 -> byteArrayOf(AgentProtocol.SSH2_AGENTC_REQUEST_IDENTITIES.toByte())
        1 -> signBody(keyBlob(r), Fuzz.bytes(r, 32), r.nextInt(4))
        2 -> signBody(keyBlob(r), Fuzz.bytes(r, r.nextInt(300)), r.nextInt())
        3 -> extBody(Pairing.EXT_COMMIT, Fuzz.bytes(r, r.nextInt(80)))
        4 -> extBody(Pairing.EXT_REVEAL, Fuzz.bytes(r, 32))
        5 -> extBody(Pairing.EXT_DONE, Fuzz.bytes(r, 32))
        else -> extBody(Pairing.EXT_COMMIT_V1, Fuzz.bytes(r, 8))
    })

    private fun put32(b: ByteArray, at: Int, v: Int) {
        for (k in 0 until 4) if (at + k < b.size) b[at + k] = (v ushr (24 - 8 * k)).toByte()
    }

    /** One hostile change to [f] (a whole frame, length prefix included). */
    private fun mutate(r: Random, f: ByteArray): ByteArray = when (r.nextInt(9)) {
        0 -> f.copyOf(r.nextInt(f.size + 1))                                        // truncation
        1 -> f.copyOf().also {                                                     // lie in the frame length
            if (it.size >= 4) put32(it, 0, if (r.nextBoolean()) LIES[r.nextInt(LIES.size)] else it.size - 4 + r.nextInt(5) - 2)
        }
        2 -> f.copyOf().also { if (it.size >= 9) put32(it, 5 + r.nextInt(it.size - 8), LIES[r.nextInt(LIES.size)]) }   // nested lie
        3 -> f.copyOf().also { repeat(1 + r.nextInt(4)) { _ -> if (it.isNotEmpty()) it[r.nextInt(it.size)] = r.nextInt(256).toByte() } }
        4 -> f + Fuzz.bytes(r, 1 + r.nextInt(64))                                  // trailing garbage
        5 -> f.copyOf().also { if (it.size > 4) it[4] = r.nextInt(256).toByte() }   // type byte
        6 -> Fuzz.bytes(r, r.nextInt(200))                                         // pure noise
        7 -> if (f.size > 6) f.copyOfRange(0, 5) + f.copyOfRange(6 + r.nextInt(f.size - 6), f.size) else f   // cut a middle piece
        else -> f.copyOf(f.size + 1 + r.nextInt(8))                                // zero padding
    }

    private fun hostile(r: Random): ByteArray {
        var f = validFrame(r)
        repeat(if (r.nextInt(8) == 0) 0 else 1 + r.nextInt(3)) { f = mutate(r, f) }
        return f
    }

    // ------------------------------------------------------------------ measuring

    /** Serves at most [chunk] bytes per read, like a slow TCP peer, and counts what was taken. */
    private class Counting(private val data: ByteArray, private val chunk: Int) : InputStream() {
        var pos = 0
        override fun read(): Int = if (pos < data.size) data[pos++].toInt() and 0xFF else -1
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            if (pos >= data.size) return -1
            val n = minOf(len, chunk, data.size - pos)
            System.arraycopy(data, pos, b, off, n)
            pos += n
            return n
        }
    }

    private val allocBean: Any? = runCatching {
        val c = Class.forName("com.sun.management.ThreadMXBean")
        ManagementFactory.getThreadMXBean().takeIf { c.isInstance(it) && c.getMethod("isThreadAllocatedMemorySupported").invoke(it) == true }
    }.getOrNull()

    /** Bytes this thread has allocated so far; -1 where the JVM cannot say. */
    @Suppress("DEPRECATION")
    private fun allocated(): Long = allocBean?.let {
        Class.forName("com.sun.management.ThreadMXBean").getMethod("getThreadAllocatedBytes", Long::class.javaPrimitiveType)
            .invoke(it, Thread.currentThread().id) as Long
    } ?: -1

    private sealed class Read {
        object Eof : Read()
        class Frame(val body: ByteArray) : Read()
        class Fail(val e: IOException) : Read()
    }

    private fun read(s: InputStream): Read = try {
        AgentProtocol.readFrame(s)?.let { Read.Frame(it) } ?: Read.Eof
    } catch (e: IOException) {
        Read.Fail(e)
    }

    // ------------------------------------------------------------------ readFrame

    @Test
    fun `readFrame is exactly the reference parser and consumes no more than it needs`() {
        Fuzz.run("readFrame/reference", 1) { _, r ->
            val b = if (r.nextInt(4) == 0) Fuzz.bytes(r, r.nextInt(40)) else hostile(r)
            val src = Counting(b, if (r.nextBoolean()) Int.MAX_VALUE else 1 + r.nextInt(3))
            val got = read(src)
            val decl = if (b.size >= 4) Fuzz.readU32(b, 0) else 0
            when {
                b.size < 4 -> {
                    assertTrue("short length field is a clean close", got is Read.Eof)
                    assertEquals(b.size, src.pos)
                }
                decl < 1 || decl > MAX_FRAME -> {
                    assertTrue("length $decl must throw IOException, was $got", got is Read.Fail)
                    assertEquals("must not touch the body of a frame it refuses", 4, src.pos)
                }
                b.size - 4 < decl -> {
                    val e = (got as? Read.Fail)?.e
                    assertTrue("truncated body must be an EOFException, was $got", e is EOFException)
                    assertEquals(b.size, src.pos)
                }
                else -> {
                    assertTrue("complete frame must parse, was $got", got is Read.Frame)
                    assertArrayEquals(b.copyOfRange(4, 4 + decl), (got as Read.Frame).body)
                    assertEquals(4 + decl, src.pos)
                    assertTrue(got.body.isNotEmpty() && got.body.size <= MAX_FRAME)
                }
            }
        }
    }

    @Test
    fun `a length prefix outside the cap allocates nothing like that size`() {
        // The cap exists so 0x7FFFFFFF in four bytes cannot make the phone allocate 2 GiB. The
        // check is on the JVM's own allocation counter, so a regression to "allocate, then
        // check" fails here rather than in the field.
        if (allocBean == null) return
        val lies = LIES.filter { it < 1 || it > MAX_FRAME }
        val budget = 32 * 1024L
        for (lie in lies) {
            repeat(3) {
                val src = ByteArrayInputStream(u32(lie) + ByteArray(16))
                val before = allocated()
                val got = read(src)
                val used = allocated() - before
                assertTrue("length $lie: $got", got is Read.Fail)
                assertTrue("length $lie allocated $used bytes (budget $budget)", used < budget)
            }
        }
        // And at the cap, the allocation is the frame and not much more.
        repeat(3) {
            val body = ByteArray(MAX_FRAME).also { it[0] = 11 }
            val src = ByteArrayInputStream(u32(MAX_FRAME) + body)
            val before = allocated()
            val got = read(src)
            val used = allocated() - before
            assertTrue(got is Read.Frame)
            assertTrue("64 KiB frame allocated $used", used < MAX_FRAME + budget)
        }
    }

    @Test
    fun `a stream of frames ends in a clean close or an IOException and never loops`() {
        Fuzz.run("readFrame/stream", 2, weight = 30) { _, r ->
            val parts = (0..r.nextInt(5)).map { hostile(r) }
            val whole = parts.fold(ByteArray(0)) { a, p -> a + p }
            val src = Counting(whole, 1 + r.nextInt(7))
            var frames = 0
            while (true) {
                val got = read(src)
                if (got !is Read.Frame) break
                frames++
                assertTrue("more frames than the bytes can hold", frames <= whole.size / 5 + 1)
            }
            assertTrue(src.pos <= whole.size)
        }
    }

    @Test
    fun `writeFrame then readFrame returns the body, byte for byte`() {
        Fuzz.run("frame/roundtrip", 3, weight = 50) { _, r ->
            val body = Fuzz.bytes(r, 1 + if (r.nextInt(20) == 0) r.nextInt(MAX_FRAME) else r.nextInt(300))
            val out = ByteArrayOutputStream()
            AgentProtocol.writeFrame(out, body)
            assertEquals(4 + body.size, out.size())
            assertArrayEquals(body, AgentProtocol.readFrame(Counting(out.toByteArray(), 1 + r.nextInt(100))))
        }
    }

    @Test
    fun `every type byte 0 to 255 survives framing and only three types are known`() {
        for (t in 0..255) {
            val body = byteArrayOf(t.toByte()) + str(ByteArray(8))
            val f = AgentProtocol.readFrame(ByteArrayInputStream(frame(body)))!!
            val r = AgentProtocol.Reader(f)
            assertEquals(t, r.type())
            r.skipType()
            assertEquals(8, r.blob().size)
        }
        val known = setOf(
            AgentProtocol.SSH2_AGENTC_REQUEST_IDENTITIES, AgentProtocol.SSH2_AGENTC_SIGN_REQUEST, AgentProtocol.SSH2_AGENTC_EXTENSION,
        )
        assertEquals(setOf(11, 13, 27), known)
    }

    // ------------------------------------------------------------------ Reader

    /** The request reading sequence of AgentService.serve for a SIGN_REQUEST. */
    private class Sign(val key: ByteArray, val data: ByteArray, val flags: Int)

    private fun decodeSign(frame: ByteArray): Sign {
        val r = AgentProtocol.Reader(frame)
        r.skipType()
        val key = r.blob()
        val data = r.blob()
        return Sign(key, data, r.int32())
    }

    /** The same parse with Long arithmetic and no shared code: null where the bytes are short. */
    private fun referenceSign(f: ByteArray): Sign? {
        var pos = 1L
        fun u32(): Long? {
            if (pos + 4 > f.size) return null
            var v = 0L
            for (k in 0 until 4) v = (v shl 8) or (f[(pos + k).toInt()].toLong() and 0xFF)
            pos += 4
            return v
        }
        fun blob(): ByteArray? {
            val n = u32() ?: return null
            if (n > Int.MAX_VALUE || pos + n > f.size) return null     // a negative Int is >= 2^31 here
            return f.copyOfRange(pos.toInt(), (pos + n).toInt()).also { pos += n }
        }
        val key = blob() ?: return null
        val data = blob() ?: return null
        val flags = u32() ?: return null
        return Sign(key, data, flags.toInt())
    }

    @Test
    fun `Reader fails only with EOFException and agrees with the reference`() {
        Fuzz.run("reader/sign", 4) { _, r ->
            val whole = hostile(r)
            val f = (read(ByteArrayInputStream(whole)) as? Read.Frame)?.body
                ?: Fuzz.bytes(r, 1 + r.nextInt(120))      // readFrame refused it: still fuzz the Reader
            val want = referenceSign(f)
            val got = try {
                decodeSign(f)
            } catch (e: EOFException) {
                null
            }
            if (want == null) assertNull("reader accepted what the reference refuses", got)
            else {
                assertNotNull("reader refused what the reference accepts", got)
                assertArrayEquals(want.key, got!!.key)
                assertArrayEquals(want.data, got.data)
                assertEquals(want.flags, got.flags)
            }
        }
    }

    @Test
    fun `a blob length that lies never yields more bytes than the frame holds`() {
        Fuzz.run("reader/lies", 5, weight = 50) { _, r ->
            val real = Fuzz.bytes(r, r.nextInt(100))
            val lie = LIES[r.nextInt(LIES.size)]
            val f = byteArrayOf(13) + u32(lie) + real
            val out = try {
                AgentProtocol.Reader(f).also { it.skipType() }.blob()
            } catch (e: EOFException) {
                null
            }
            if (out != null) {
                assertEquals(lie, out.size)
                assertTrue(out.size <= real.size)
            } else {
                assertTrue("a length that fits was refused: $lie vs ${real.size}", lie < 0 || lie > real.size)
            }
        }
    }

    @Test
    fun `Reader walks a sequence of blobs and ints on random bytes without any other exception`() {
        Fuzz.run("reader/walk", 6, weight = 50) { _, r ->
            val f = Fuzz.bytes(r, 1 + r.nextInt(64)).also { if (r.nextBoolean() && it.size > 8) put32(it, 1 + r.nextInt(it.size - 4), r.nextInt(12)) }
            val rd = AgentProtocol.Reader(f)
            rd.skipType()
            var steps = 0
            try {
                while (steps++ < 200) { if (r.nextBoolean()) rd.blob() else rd.int32() }
            } catch (e: EOFException) {
                // the one documented way to stop
            }
        }
    }

    @Test
    fun `answers the agent builds parse back with the Reader`() {
        Fuzz.run("answers/roundtrip", 7, weight = 30) { _, r ->
            val keys = (0 until r.nextInt(6)).map { Fuzz.bytes(r, r.nextInt(150)) }
            val comment = String(Fuzz.bytes(r, r.nextInt(20)).map { (0x20 + (it.toInt() and 0x3F)).toByte() }.toByteArray(), Charsets.US_ASCII)
            val a = AgentProtocol.Reader(AgentProtocol.identitiesAnswer(keys, comment))
            assertEquals(AgentProtocol.SSH2_AGENT_IDENTITIES_ANSWER, a.type())
            a.skipType()
            assertEquals(keys.size, a.int32())
            for (k in keys) {
                assertArrayEquals(k, a.blob())
                assertEquals(comment, String(a.blob(), Charsets.US_ASCII))
            }
            val sig = Fuzz.bytes(r, r.nextInt(130))
            val s = AgentProtocol.Reader(AgentProtocol.signResponse(sig))
            assertEquals(AgentProtocol.SSH2_AGENT_SIGN_RESPONSE, s.type())
            s.skipType()
            assertArrayEquals(sig, s.blob())
            val parts = (0 until r.nextInt(4)).map { Fuzz.bytes(r, r.nextInt(40)) }
            val ok = AgentProtocol.Reader(AgentProtocol.success(*parts.toTypedArray()))
            assertEquals(AgentProtocol.SSH2_AGENT_SUCCESS, ok.type())
            ok.skipType()
            for (p in parts) assertArrayEquals(p, ok.blob())
        }
    }

    // ------------------------------------------------------------------ the sign policy

    @Test
    fun `refusal lets a request through for one input only - a known key and exactly 32 bytes`() {
        for (known in listOf(true, false)) {
            for (n in 0..200) {
                val why = AgentProtocol.refusal(known, ByteArray(n))
                if (known && n == AgentProtocol.CHALLENGE_BYTES) assertNull(why) else assertFalse("known=$known n=$n", why.isNullOrEmpty())
            }
        }
        Fuzz.run("refusal/random", 8) { _, r ->
            val known = r.nextBoolean()
            val n = if (r.nextInt(50) == 0) 32 else if (r.nextBoolean()) r.nextInt(70) else r.nextInt(5000)
            val why = AgentProtocol.refusal(known, Fuzz.bytes(r, n))
            assertEquals("known=$known n=$n", known && n == 32, why == null)
            if (why != null) assertTrue(why.isNotEmpty())
        }
    }

    @Test
    fun `no mutated request signs unless it names a paired key and carries a 32 byte challenge`() {
        // The service's decision, end to end on the parsing side: whatever bytes arrive, the
        // outcome "put it to the user" needs a key blob equal to a paired computer's and a
        // data blob of exactly 32 bytes. A near-miss key (one bit off) is not that key.
        val paired = (0 until 3).map { keyBlob(Random(100L + it)) }
        Fuzz.run("refusal/mutated", 9) { _, r ->
            val key = if (r.nextInt(3) == 0) paired[r.nextInt(paired.size)].copyOf() else keyBlob(r)
            if (r.nextInt(4) == 0) r.nextInt(key.size).let { at -> key[at] = (key[at].toInt() xor (1 shl r.nextInt(8))).toByte() }
            val data = Fuzz.bytes(r, if (r.nextBoolean()) 32 else r.nextInt(80))
            var f = frame(signBody(key, data, r.nextInt()))
            repeat(r.nextInt(3)) { f = mutate(r, f) }
            val body = (read(ByteArrayInputStream(f)) as? Read.Frame)?.body ?: return@run
            if (body[0].toInt() != AgentProtocol.SSH2_AGENTC_SIGN_REQUEST) return@run
            val sign = try { decodeSign(body) } catch (e: EOFException) { return@run }
            val host = paired.firstOrNull { it.contentEquals(sign.key) }
            val why = AgentProtocol.refusal(host != null, sign.data)
            if (why == null) {
                assertNotNull("signed for a key that is not paired", host)
                assertEquals(32, sign.data.size)
            }
        }
    }
}
