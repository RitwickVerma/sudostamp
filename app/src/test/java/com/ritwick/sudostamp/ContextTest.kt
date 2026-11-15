package com.ritwick.sudostamp

import com.ritwick.sudostamp.Fuzz.str
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The description of a sudo (context-v1@sudostamp): the parser of bytes a LAN peer chooses, the
 * single-use box that holds it, and the reader of the host tool's script-run command line.
 * None of it may ever decide anything: it is text for the user's eyes, so the properties that
 * matter are "what is shown is what the bytes are" and "bounded".
 */
class ContextTest {

    /** What serve() has done when it calls parseContext: type and name consumed, then the rest. */
    private fun parse(vararg after: ByteArray): String? {
        val r = AgentProtocol.Reader(
            byteArrayOf(AgentProtocol.SSH2_AGENTC_EXTENSION.toByte()) + str(AgentProtocol.EXT_CONTEXT) +
                after.fold(ByteArray(0)) { a, b -> a + b }
        )
        r.skipType()
        assertEquals(AgentProtocol.EXT_CONTEXT, String(r.blob(), Charsets.US_ASCII))
        return AgentProtocol.parseContext(r)
    }

    private fun parseText(s: String) = parse(str(s.toByteArray(Charsets.UTF_8)))

    // ------------------------------------------------------------------ parseContext

    @Test
    fun `a plain command is returned as it is`() {
        assertEquals("sudo pacman -Syu", parseText("sudo pacman -Syu"))
        assertEquals("sudo echo h\u00e9llo \u4e2d\u6587 \uD83D\uDE00", parseText("sudo echo h\u00e9llo \u4e2d\u6587 \uD83D\uDE00"))
    }

    @Test
    fun `nothing else is collapsed or changed`() {
        assertEquals("a  b   c", parseText("a  b   c"))
        assertEquals("sudo -k -- /usr/bin/x 'quoted' \"q\" \\ ;&|", parseText("sudo -k -- /usr/bin/x 'quoted' \"q\" \\ ;&|"))
    }

    @Test
    fun `leading and trailing space is trimmed`() {
        assertEquals("sudo ls", parseText("  \u00a0 sudo ls \u3000 "))
    }

    @Test
    fun `empty or blank is null`() {
        assertNull(parseText(""))
        assertNull(parseText("   \u00a0 "))
    }

    @Test
    fun `trailing bytes after the string are refused`() {
        assertNull(parse(str("sudo ls"), byteArrayOf(0)))
        assertNull(parse(str("sudo ls"), str("sudo ls")))
    }

    @Test
    fun `a missing or truncated string is null, never an exception`() {
        assertNull(parse())
        assertNull(parse(byteArrayOf(0, 0, 0)))
        assertNull(parse(Fuzz.u32(10) + "short".toByteArray()))
        assertNull(parse(Fuzz.u32(-1)))
        assertNull(parse(Fuzz.u32(Int.MAX_VALUE)))
    }

    @Test
    fun `the size limit is 2048 bytes of payload`() {
        assertNotNull(parseText("a".repeat(2048)))      // accepted, then cut to 512 code points
        assertNull(parseText("a".repeat(2049)))
        // Bytes, not characters: 1025 two-byte characters are 2050 bytes.
        assertNull(parseText("\u00e9".repeat(1025)))
        assertNotNull(parseText("\u00e9".repeat(1024)))
    }

    @Test
    fun `malformed UTF-8 is refused, not repaired`() {
        val bad = listOf(
            byteArrayOf(0x73, 0xC3.toByte()),                                 // truncated sequence
            byteArrayOf(0x73, 0xFF.toByte(), 0x73),                           // invalid byte
            byteArrayOf(0xC0.toByte(), 0xAF.toByte()),                        // overlong '/'
            byteArrayOf(0xED.toByte(), 0xA0.toByte(), 0x80.toByte()),         // an encoded surrogate
            byteArrayOf(0xF4.toByte(), 0x90.toByte(), 0x80.toByte(), 0x80.toByte()), // beyond U+10FFFF
            byteArrayOf(0x80.toByte()),                                       // lone continuation
        )
        for (b in bad) assertNull(b.joinToString(" ") { "%02x".format(it) }, parse(str(b)))
    }

    private fun forbidden(cp: Int): Boolean =
        cp <= 0x1F || cp in 0x7F..0x9F || cp in 0x200B..0x200F || cp in 0x2028..0x202E ||
            cp in 0x2060..0x2069 || cp == 0x061C || cp == 0xFEFF

    @Test
    fun `every control and invisible character class becomes a visible question mark`() {
        val classes = (0x00..0x1F) + (0x7F..0x9F) + (0x200B..0x200F) + (0x202A..0x202E) + (0x2060..0x2069) +
            listOf(0xFEFF, 0x2028, 0x2029, 0x061C)
        for (cp in classes) {
            val got = parseText("a" + String(Character.toChars(cp)) + "b")
            assertEquals("U+%04X".format(cp), "a?b", got)
        }
    }

    @Test
    fun `a bidi override cannot hide what the text says`() {
        // U+202E reverses what follows on screen: this would read "sudo rm -rf /tmp/x" in a
        // viewer that obeys it. Shown with the override made visible, it is what the bytes are.
        val sneaky = "sudo \u202Ex/pmt/ fr- mr\u202C"
        assertEquals("sudo ?x/pmt/ fr- mr?", parseText(sneaky))
        assertEquals("sudo ?echo hi?", parseText("sudo \u2066echo hi\u2069"))
    }

    @Test
    fun `NUL ESC newline and tab are visible too`() {
        assertEquals("sudo ?[31mrm?x?y?z", parseText("sudo \u001B[31mrm\u0000x\ny\tz"))
    }

    @Test
    fun `ordinary characters next to the stripped ones survive`() {
        // U+00A0 and U+3000 are spaces, not controls; U+00AD (soft hyphen) and U+0301 are left alone.
        assertEquals("a\u00a0b\u3000c\u00add\u00e9\u0301", parseText("a\u00a0b\u3000c\u00add\u00e9\u0301"))
    }

    @Test
    fun `long text is cut at 512 code points with an ellipsis`() {
        val exactly = "x".repeat(512)
        assertEquals(exactly, parseText(exactly))
        val cut = parseText("x".repeat(513))!!
        assertEquals(512, cut.codePointCount(0, cut.length))
        assertTrue(cut.endsWith("\u2026"))
        assertEquals("x".repeat(511) + "\u2026", cut)
    }

    @Test
    fun `the cut never splits a surrogate pair`() {
        assertNull("2400 bytes: refused outright", parseText("\uD83D\uDE00".repeat(600)))
        // 113 + 400 = 513 code points in 1713 bytes: the cut lands inside the emoji run.
        val cut = parseText("x".repeat(113) + "\uD83D\uDE00".repeat(400))!!
        assertEquals(512, cut.codePointCount(0, cut.length))
        assertEquals("\u2026", cut.substring(cut.length - 1))
        assertEquals("x".repeat(113) + "\uD83D\uDE00".repeat(398) + "\u2026", cut)
    }

    @Test
    fun `sanitising twice changes nothing`() {
        for (s in listOf("sudo ls", "x".repeat(900), "a\u202Eb", "\uD83D\uDE00".repeat(700))) {
            val once = AgentProtocol.sanitize(s, 512)!!
            assertEquals(once, AgentProtocol.sanitize(once, 512))
        }
    }

    @Test
    fun `the result never contains a forbidden character`() {
        val all = (0..0x2FFF).joinToString("") { String(Character.toChars(it)) }.take(900)
        val got = AgentProtocol.sanitize(all, 512)!!
        got.codePoints().forEach { assertFalse("U+%04X".format(it), forbidden(it)) }
    }

    // ------------------------------------------------------------------ ContextBox

    @Test
    fun `a description is single use`() {
        val b = ContextBox()
        b.put("10.0.0.2", "sudo ls", 1_000)
        assertEquals(ContextBox.Seen("sudo ls", false), b.take("10.0.0.2", 1_001))
        assertNull(b.take("10.0.0.2", 1_002))
    }

    @Test
    fun `nothing pending is null`() {
        assertNull(ContextBox().take("10.0.0.2", 0))
    }

    @Test
    fun `it expires exactly at the ttl`() {
        val b = ContextBox(ttlMs = 15_000)
        b.put("c", "x", 100)
        assertEquals("one ms before", "x", b.take("c", 100 + 14_999)?.text)
        b.put("c", "x", 100)
        assertNull("at the ttl", b.take("c", 100 + 15_000))
        b.put("c", "x", 100)
        assertNull("after", b.take("c", 100 + 99_000))
    }

    @Test
    fun `an expired entry is replaced, not conflicted with`() {
        val b = ContextBox(ttlMs = 1_000)
        b.put("c", "old", 0)
        b.put("c", "new", 1_000)
        assertEquals(ContextBox.Seen("new", false), b.take("c", 1_001))
    }

    @Test
    fun `the first text is kept and a different one conflicts`() {
        val b = ContextBox()
        b.put("c", "sudo ls", 0)
        b.put("c", "sudo rm -rf /", 10)
        val seen = b.take("c", 20)
        assertEquals(ContextBox.Seen(null, true), seen)
        assertNull("a contested description is never handed out", seen!!.text)
    }

    @Test
    fun `the same text again is not a conflict, and does not extend the ttl`() {
        val b = ContextBox(ttlMs = 1_000)
        b.put("c", "x", 0)
        b.put("c", "x", 900)
        assertNull("the clock runs from the first", b.take("c", 1_000))
        b.put("c", "x", 0)
        b.put("c", "x", 500)
        assertEquals(ContextBox.Seen("x", false), b.take("c", 600))
    }

    @Test
    fun `a conflict is consumed with the entry`() {
        val b = ContextBox()
        b.put("c", "a", 0); b.put("c", "b", 1)
        assertTrue(b.take("c", 2)!!.conflicted)
        b.put("c", "b", 3)
        assertEquals(ContextBox.Seen("b", false), b.take("c", 4))
    }

    @Test
    fun `clients are isolated`() {
        val b = ContextBox()
        b.put("a", "one", 0)
        b.put("b", "two", 0)
        b.put("a", "other", 1)
        assertEquals(ContextBox.Seen("two", false), b.take("b", 2))
        assertEquals(ContextBox.Seen(null, true), b.take("a", 2))
        assertNull(b.take("c", 2))
    }

    @Test
    fun `the oldest client is evicted beyond the maximum`() {
        val b = ContextBox(maxClients = 3)
        for (i in 1..4) b.put("c$i", "t$i", i.toLong())
        assertNull("c1 was the oldest", b.take("c1", 10))
        for (i in 2..4) assertEquals("t$i", b.take("c$i", 10)?.text)
    }

    @Test
    fun `a flood of clients cannot grow the box`() {
        val b = ContextBox(maxClients = 16)
        for (i in 0 until 10_000) b.put("10.0.${i / 250}.${i % 250}", "x", i.toLong())
        var held = 0
        for (i in 0 until 10_000) if (b.take("10.0.${i / 250}.${i % 250}", 10_000) != null) held++
        assertEquals(16, held)
    }

    // ------------------------------------------------------------------ parseRun

    private val sha = "0123456789abcdef".repeat(4)

    @Test
    fun `a script run is read in all its allowed shapes`() {
        val want = Run(sha, "claude", "update the packages")
        assertEquals(want, parseRun("sudo -k -- /usr/local/sbin/sudostamp-run $sha claude -- update the packages"))
        assertEquals(want, parseRun("sudo -k /usr/local/sbin/sudostamp-run $sha claude -- update the packages"))
        assertEquals(want, parseRun("sudo -- /usr/local/sbin/sudostamp-run $sha claude -- update the packages"))
        assertEquals(want, parseRun("sudo /usr/local/sbin/sudostamp-run $sha claude -- update the packages"))
        assertEquals(want, parseRun("/usr/bin/sudo sudostamp-run $sha claude -- update the packages"))
    }

    @Test
    fun `the reason keeps its own spacing`() {
        assertEquals("a  b -- c", parseRun("sudo sudostamp-run $sha x -- a  b -- c")?.why)
    }

    @Test
    fun `a script run needs sudo, the tool and a 64 character lowercase hash`() {
        assertNull(parseRun("doas sudostamp-run $sha claude -- why"))
        assertNull(parseRun("sudo other-tool $sha claude -- why"))
        assertNull(parseRun("sudo sudostamp-run ${sha.dropLast(1)} claude -- why"))
        assertNull(parseRun("sudo sudostamp-run ${sha}0 claude -- why"))
        assertNull(parseRun("sudo sudostamp-run ${sha.uppercase()} claude -- why"))
        assertNull(parseRun("sudo sudostamp-run ${sha.dropLast(1)}g claude -- why"))
        assertNull(parseRun("sudo -k -k sudostamp-run $sha claude -- why"))
        assertNull(parseRun("sudo -- -k sudostamp-run $sha claude -- why"))
        assertNull(parseRun("sudo -u root sudostamp-run $sha claude -- why"))
    }

    @Test
    fun `the agent name follows its pattern`() {
        for (ok in listOf("a", "0", "claude-code", "a.b_c-d", "a".repeat(32))) {
            assertEquals(ok, ok, parseRun("sudo sudostamp-run $sha $ok -- why")?.agent)
        }
        for (bad in listOf("A", "-a", ".a", "_a", "a".repeat(33), "a/b", "a b", "\u00e9", "")) {
            assertNull(bad, parseRun("sudo sudostamp-run $sha $bad -- why"))
        }
    }

    @Test
    fun `the reason is required`() {
        assertNull(parseRun("sudo sudostamp-run $sha claude --"))
        assertNull(parseRun("sudo sudostamp-run $sha claude -- "))
        assertNull(parseRun("sudo sudostamp-run $sha claude -- \u00a0"))
        assertNull(parseRun("sudo sudostamp-run $sha claude why"))
        assertNull(parseRun("sudo sudostamp-run $sha claude"))
    }

    @Test
    fun `extra spaces between the structural tokens are not a script run`() {
        assertNull(parseRun("sudo  sudostamp-run $sha claude -- why"))
        assertNull(parseRun("sudo sudostamp-run  $sha claude -- why"))
        assertNull(parseRun("sudo sudostamp-run $sha  claude -- why"))
        assertNull(parseRun("sudo sudostamp-run $sha claude  -- why"))
        assertNull(parseRun(" sudo sudostamp-run $sha claude -- why"))
    }

    @Test
    fun `an ordinary command and the empty string are not a run`() {
        assertNull(parseRun(""))
        assertNull(parseRun("sudo pacman -Syu"))
        assertNull(parseRun("sudo"))
    }

    @Test
    fun `the screen shows sixteen hex digits in groups of four`() {
        assertEquals("0123 4567 89ab cdef", Run(sha, "a", "w").shortSha)
    }

    @Test
    fun `the one-line description is agent and reason, or the command`() {
        assertEquals("claude: update", describeContext("sudo -k -- /x/sudostamp-run $sha claude -- update"))
        assertEquals("sudo pacman -Syu", describeContext("sudo pacman -Syu"))
    }
}
