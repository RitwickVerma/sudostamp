package com.ritwick.sudostamp

import com.ritwick.sudostamp.Fuzz.str
import com.ritwick.sudostamp.Fuzz.u32
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

/**
 * Properties of the description parsers, over seeded random input (FuzzSupport):
 *
 *  - parseContext never throws; it is the reference below (a strict UTF-8 reader, scrubber and
 *    cutter written without its code); what it returns has none of the forbidden characters, is
 *    trimmed and is at most 512 code points;
 *  - parseRun never throws, agrees with a regular-expression reference, and reads back every
 *    command the host tool could have generated;
 *  - ContextBox agrees with a list-based model through random puts and takes, and never holds
 *    more than its maximum.
 */
class ContextFuzzTest {

    // ------------------------------------------------------------------ references

    /** Strict UTF-8 (RFC 3629) by hand: shortest forms, no surrogates, nothing above U+10FFFF. */
    private fun refDecode(b: ByteArray): IntArray? {
        val out = ArrayList<Int>()
        var i = 0
        fun cont(at: Int) = at < b.size && (b[at].toInt() and 0xC0) == 0x80
        while (i < b.size) {
            val x = b[i].toInt() and 0xFF
            val cp: Int
            when {
                x < 0x80 -> { cp = x; i += 1 }
                x in 0xC2..0xDF -> {
                    if (!cont(i + 1)) return null
                    cp = ((x and 0x1F) shl 6) or (b[i + 1].toInt() and 0x3F); i += 2
                }
                x in 0xE0..0xEF -> {
                    if (!cont(i + 1) || !cont(i + 2)) return null
                    cp = ((x and 0x0F) shl 12) or ((b[i + 1].toInt() and 0x3F) shl 6) or (b[i + 2].toInt() and 0x3F)
                    if (cp < 0x800 || cp in 0xD800..0xDFFF) return null
                    i += 3
                }
                x in 0xF0..0xF4 -> {
                    if (!cont(i + 1) || !cont(i + 2) || !cont(i + 3)) return null
                    cp = ((x and 0x07) shl 18) or ((b[i + 1].toInt() and 0x3F) shl 12) or
                        ((b[i + 2].toInt() and 0x3F) shl 6) or (b[i + 3].toInt() and 0x3F)
                    if (cp < 0x10000 || cp > 0x10FFFF) return null
                    i += 4
                }
                else -> return null
            }
            out.add(cp)
        }
        return out.toIntArray()
    }

    // The rule, stated from the Unicode side (AgentProtocol.invisible): controls, format, line and
    // paragraph separators, surrogates, private use, unassigned, and the default-ignorable or
    // blank-looking characters that are none of those.
    private fun forbidden(cp: Int): Boolean = when (Character.getType(cp)) {
        Character.CONTROL.toInt(), Character.FORMAT.toInt(), Character.LINE_SEPARATOR.toInt(),
        Character.PARAGRAPH_SEPARATOR.toInt(), Character.SURROGATE.toInt(),
        Character.PRIVATE_USE.toInt(), Character.UNASSIGNED.toInt() -> true
        else -> cp in setOf(0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0, 0x17B4, 0x17B5, 0x2800) ||
            cp in 0x180B..0x180F || cp in 0xFE00..0xFE0F || cp in 0xE0100..0xE01EF
    }

    private fun oddSpace(cp: Int) = cp != 0x20 && Character.getType(cp) == Character.SPACE_SEPARATOR.toInt()

    private fun space(cp: Int) = Character.isWhitespace(cp) || Character.isSpaceChar(cp)

    private fun refContext(payload: ByteArray): String? {
        if (payload.size > 2048) return null
        val cps = (refDecode(payload) ?: return null)
            .map { if (forbidden(it)) '?'.code else if (oddSpace(it)) ' '.code else it }.toMutableList()
        while (cps.isNotEmpty() && space(cps.first())) cps.removeAt(0)
        while (cps.isNotEmpty() && space(cps.last())) cps.removeAt(cps.size - 1)
        if (cps.isEmpty()) return null
        val kept = if (cps.size > 512) cps.take(511) + 0x2026 else cps
        return kept.joinToString("") { String(Character.toChars(it)) }
    }

    private val RUN = Regex(
        "^(?:[^ ]*/)?sudo (?:-k )?(?:-- )?/usr/local/sbin/sudostamp-run ([0-9a-f]{64}) ([a-z0-9][a-z0-9._-]{0,31}) -- (.*)$",
        RegexOption.DOT_MATCHES_ALL
    )

    private fun refRun(c: String): Run? {
        val m = RUN.matchEntire(c) ?: return null
        val why = m.groupValues[3].trim()
        return if (why.isEmpty()) null else Run(m.groupValues[1], m.groupValues[2], why)
    }

    // ------------------------------------------------------------------ generators

    /** A code point from a pool that is rich in what the scrubber must catch. */
    private fun codePoint(r: Random): Int = when (r.nextInt(10)) {
        0 -> r.nextInt(0x20)
        1 -> 0x7F + r.nextInt(0x21)
        2 -> intArrayOf(0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
            0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF, 0x2028, 0x2029, 0x061C, 0xA0, 0x3000, 0x2003)[r.nextInt(22)]
        3, 4 -> 0x20 + r.nextInt(0x5F)
        5 -> 0xA0 + r.nextInt(0x700)
        6 -> 0x800 + r.nextInt(0xD800 - 0x800)
        7 -> 0xE000 + r.nextInt(0x2000)
        8 -> 0x10000 + r.nextInt(0x100000)
        else -> 0x20
    }

    private fun utf8(cps: List<Int>): ByteArray =
        cps.joinToString("") { String(Character.toChars(it)) }.toByteArray(Charsets.UTF_8)

    private fun payload(r: Random): ByteArray = when (r.nextInt(6)) {
        0 -> Fuzz.bytes(r, r.nextInt(120))
        1 -> Fuzz.bytes(r, 2000 + r.nextInt(120))                      // around the size limit
        2 -> utf8(List(r.nextInt(80)) { codePoint(r) })
        3 -> utf8(List(480 + r.nextInt(60)) { codePoint(r) })           // around the 512 cut
        4 -> utf8(List(r.nextInt(30)) { codePoint(r) }).let { b ->      // valid, then damaged
            if (b.isEmpty()) b else b.copyOf().also { it[r.nextInt(it.size)] = r.nextInt(256).toByte() }
        }
        else -> utf8(List(r.nextInt(600)) { if (r.nextInt(8) == 0) codePoint(r) else 'a'.code + r.nextInt(26) })
    }

    private fun reader(vararg parts: ByteArray) = AgentProtocol.Reader(
        byteArrayOf(AgentProtocol.SSH2_AGENTC_EXTENSION.toByte()) + str(AgentProtocol.EXT_CONTEXT) +
            parts.fold(ByteArray(0)) { a, b -> a + b }
    ).also { it.skipType(); it.blob() }

    // ------------------------------------------------------------------ properties

    @Test
    fun `parseContext is the reference, bounded and clean`() = Fuzz.run("context.parse", 0xC0DE1) { _, r ->
        val p = payload(r)
        val got = AgentProtocol.parseContext(reader(str(p)))
        assertEquals(refContext(p), got)
        if (got != null) {
            val n = got.codePointCount(0, got.length)
            assertTrue(n in 1..512)
            got.codePoints().forEach { assertFalse("U+%04X".format(it), forbidden(it)) }
            assertEquals(got, got.trim { it.isWhitespace() })
            assertFalse("no lone surrogate", got.indices.any { Character.isLowSurrogate(got[it]) && (it == 0 || !Character.isHighSurrogate(got[it - 1])) })
        }
    }

    @Test
    fun `parseContext refuses what is not exactly one string`() = Fuzz.run("context.frame", 0xC0DE2) { _, r ->
        val p = utf8(List(1 + r.nextInt(40)) { 'a'.code + r.nextInt(26) })
        val ok = AgentProtocol.parseContext(reader(str(p)))
        assertTrue(ok != null)
        // Trailing bytes, any; a truncated string; a lying length: never a result, never a throw.
        assertNull(AgentProtocol.parseContext(reader(str(p), Fuzz.bytes(r, 1 + r.nextInt(12)))))
        val whole = str(p)
        assertNull(AgentProtocol.parseContext(reader(whole.copyOf(r.nextInt(whole.size)))))
        assertNull(AgentProtocol.parseContext(reader(u32(p.size + 1 + r.nextInt(50)) + p)))
    }

    private val AGENT_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"

    private fun agent(r: Random): String {
        val n = 1 + r.nextInt(32)
        val sb = StringBuilder().append(AGENT_CHARS[r.nextInt(AGENT_CHARS.length)])
        while (sb.length < n) sb.append((AGENT_CHARS + "._-")[r.nextInt(AGENT_CHARS.length + 3)])
        return sb.toString()
    }

    private fun sha(r: Random) = Fuzz.bytes(r, 32).joinToString("") { "%02x".format(it) }

    private fun commandWords(r: Random): String = List(1 + r.nextInt(8)) {
        String(Character.toChars(codePoint(r).let { cp -> if (cp == ' '.code) 'z'.code else cp })).repeat(1 + r.nextInt(5))
    }.joinToString(" ")

    @Test
    fun `parseRun reads back what the tool generates`() = Fuzz.run("run.roundtrip", 0xC0DE3) { _, r ->
        val a = agent(r); val s = sha(r); val why = commandWords(r).trim { it.isWhitespace() }
        if (why.isEmpty()) return@run
        val dir = listOf("", "/usr/local/sbin/", "./", "/a b/".replace(" ", "_"))[r.nextInt(4)]
        val pre = listOf("sudo ", "/usr/bin/sudo ")[r.nextInt(2)] +
            (if (r.nextBoolean()) "-k " else "") + (if (r.nextBoolean()) "-- " else "")
        val cmd = "${pre}${dir}sudostamp-run $s $a -- $why"
        // Only the installed runner reads as an agent's run; the same words anywhere else do not.
        assertEquals(cmd, if (dir == "/usr/local/sbin/") Run(s, a, why) else null, parseRun(cmd))
    }

    @Test
    fun `parseRun never throws and is the reference`() = Fuzz.run("run.reference", 0xC0DE4) { _, r ->
        val a = agent(r); val s = sha(r)
        val base = "sudo -k -- /usr/local/sbin/sudostamp-run $s $a -- some words here"
        val cmd = when (r.nextInt(5)) {
            0 -> base.toCharArray().also { c -> repeat(1 + r.nextInt(3)) { c[r.nextInt(c.size)] = (0x20 + r.nextInt(0x5F)).toChar() } }.concatToString()
            1 -> base.substring(0, r.nextInt(base.length + 1))
            2 -> base.replaceFirst(" ", " ".repeat(1 + r.nextInt(3)))
            3 -> String(CharArray(r.nextInt(80)) { (r.nextInt(0x60) + 0x20).toChar() })
            else -> base.split(' ').shuffled(r).joinToString(" ")
        }
        assertEquals(cmd, refRun(cmd), parseRun(cmd))
        describeContext(cmd)           // never throws either
    }

    @Test
    fun `the box agrees with a model and stays bounded`() = Fuzz.run("context.box", 0xC0DE5, weight = 25) { _, r ->
        val ttl = 1 + r.nextInt(50).toLong()
        val max = 1 + r.nextInt(5)
        val box = ContextBox(ttl, max)
        class M(val client: String, val text: String, val at: Long, var conflicted: Boolean)
        val model = ArrayList<M>()       // oldest first
        var now = 0L
        repeat(60) {
            now += r.nextInt(ttl.toInt() / 2 + 2)
            val c = "c${r.nextInt(max + 3)}"
            if (r.nextInt(3) != 0) {
                val t = "t${r.nextInt(3)}"
                box.put(c, t, now)
                model.removeAll { now - it.at >= ttl }
                val e = model.firstOrNull { it.client == c }
                if (e != null) { if (e.text != t) e.conflicted = true } else {
                    model.add(M(c, t, now, false))
                    while (model.size > max) model.removeAt(0)
                }
            } else {
                val got = box.take(c, now)
                val e = model.firstOrNull { it.client == c }
                model.remove(e)
                val want = if (e == null || now - e.at >= ttl) null
                else if (e.conflicted) ContextBox.Seen(null, true) else ContextBox.Seen(e.text, false)
                assertEquals(want, got)
            }
            assertTrue(model.size <= max)
        }
    }
}
