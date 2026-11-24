package com.ritwick.sudostamp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.time.ZoneId

/** The request history: bounded, versioned, and unable to crash the agent. */
class HistoryTest {

    @get:Rule val tmp = TemporaryFolder()

    private val host = "0123456789abcdef"
    private var t = 1_700_000_000_000L

    private fun entry(
        v: Verdict = Verdict.APPROVED, r: Refusal? = null, id: String? = host,
        label: String = "edith", peer: String = "192.0.2.7", at: Long = t++, command: String? = null,
    ) = HistoryEntry(at, v, r, id, label, peer, command = command)

    private fun refused(r: Refusal, id: String? = host, peer: String = "192.0.2.7", at: Long = t++) =
        entry(Verdict.REFUSED, r, id, if (id == null) "" else "edith", peer, at)

    @Test
    fun `keeps only the last 100, newest first`() {
        val h = History()
        repeat(150) { h.record(entry(peer = "10.0.0.$it")) }
        val list = h.entries()
        assertEquals(100, list.size)
        assertEquals("newest first", "10.0.0.149", list.first().peer)
        assertEquals("10.0.0.50", list.last().peer)
    }

    @Test
    fun `round trips through the file with every field`() {
        val f = File(tmp.root, "h.txt")
        val h = History(f)
        h.record(entry(Verdict.DENIED_NOTIFICATION, label = "lab\ttop \u00e9\u4e2d", peer = "fe80::1"))
        h.record(refused(Refusal.UNKNOWN_KEY, id = null, peer = "198.51.100.9"))
        val back = History(f).entries()
        assertEquals(h.entries(), back)
        assertEquals(2, back.size)
        assertNull("an unpaired peer has no computer", back.first().hostId)
        assertEquals("lab top \u00e9\u4e2d", back.last().label)   // control characters become spaces
    }

    @Test
    fun `a missing or empty file starts empty`() {
        assertTrue(History(File(tmp.root, "nope.txt")).entries().isEmpty())
        val f = File(tmp.root, "empty.txt").apply { writeText("") }
        assertTrue(History(f).entries().isEmpty())
    }

    @Test
    fun `a corrupt file starts empty and does not throw`() {
        for (junk in listOf(
            "\u0000\u0001\u0002garbage", "not a header\n1\t2\t3", "sudostamp-history 2\n1\ta\t-\t1\t\t\t",
            "sudostamp-history 1\n\u0000\u0000\n", "sudostamp-history", "\n\n\n",
        )) {
            val f = File(tmp.root, "c.txt").apply { writeText(junk) }
            assertTrue("[$junk]", History(f).entries().isEmpty())
        }
        // raw bytes that are not UTF-8
        val f = File(tmp.root, "bin.txt").apply { writeBytes(ByteArray(300) { (it * 37).toByte() }) }
        assertTrue(History(f).entries().isEmpty())
    }

    @Test
    fun `a damaged line is skipped and the others survive`() {
        val good = History.encode(listOf(entry(peer = "a"), entry(peer = "b")))
        val lines = good.lines().toMutableList()
        lines.add(2, "12\tzz\t-\t1\t\t\t")               // unknown verdict
        lines.add(2, "x\ta\t-\t1\t\t\t")                 // not a number
        lines.add(2, "5\tr\t-\t1\t\t\t")                 // refused without a reason
        lines.add(2, "5\ta\tk\t1\t\t\t")                 // a reason on a non-refusal
        lines.add(2, "5\ta\t-\t0\t\t\t")                 // zero count
        lines.add(2, "5\ta\t-\t1\t!!!notbase64\t\t")
        lines.add(2, "5\ta\t-\t1\tZXZpbA==\t\t")         // host id "evil": not one of ours
        val back = History.decode(lines.joinToString("\n"))
        assertEquals(listOf("a", "b"), back.map { it.peer })
    }

    @Test
    fun `an oversized file is not read`() {
        val f = File(tmp.root, "big.txt")
        f.writeText(History.encode(listOf(entry())) + "x".repeat(300 * 1024))
        assertTrue(History(f).entries().isEmpty())
    }

    @Test
    fun `a file with more than the cap is trimmed on load`() {
        val f = File(tmp.root, "many.txt")
        f.writeText(History.encode((1..250).map { entry(peer = "p$it") }))
        assertEquals(100, History(f).entries().size)
    }

    @Test
    fun `clear empties it and removes the file`() {
        val f = File(tmp.root, "h.txt")
        val h = History(f)
        h.record(entry())
        assertTrue(f.exists())
        h.clear()
        assertTrue(h.entries().isEmpty())
        assertFalse(f.exists())
        assertTrue(History(f).entries().isEmpty())
    }

    @Test
    fun `a write that cannot happen never throws`() {
        val h = History(File(File(tmp.root, "no-such-dir"), "h.txt"))
        h.record(entry())
        assertEquals("still in memory", 1, h.entries().size)
    }

    @Test
    fun `an unwritable directory does not break recording`() {
        // The path's parent is a file: both the temp write and the rename must fail quietly.
        val blocker = File(tmp.root, "file").apply { writeText("x") }
        val h = History(File(blocker, "h.txt"))
        h.record(entry())
        assertEquals(1, h.entries().size)
    }

    @Test
    fun `identical refusals from one peer coalesce into a count`() {
        val h = History()
        repeat(5) { h.record(refused(Refusal.UNKNOWN_KEY, id = null, peer = "198.51.100.9", at = 1_000L * (it + 1))) }
        assertEquals(1, h.entries().size)
        assertEquals(5, h.entries().single().count)
        assertEquals("the latest time", 5_000L, h.entries().single().at)
    }

    @Test
    fun `refusals that differ in reason or peer or are far apart stay apart`() {
        val h = History()
        h.record(refused(Refusal.UNKNOWN_KEY, id = null, peer = "a", at = 1_000))
        h.record(refused(Refusal.UNKNOWN_KEY, id = null, peer = "b", at = 2_000))
        h.record(refused(Refusal.NOT_A_CHALLENGE, peer = "b", at = 3_000))
        h.record(refused(Refusal.NOT_A_CHALLENGE, peer = "b", at = 3_000 + History.COALESCE_WINDOW_MS))
        assertEquals(4, h.entries().size)
    }

    @Test
    fun `outside-LAN refusals coalesce whatever the peer, so a scan cannot flush the log`() {
        val h = History()
        h.record(entry(at = 500))
        repeat(1_000) { h.record(refused(Refusal.OUTSIDE_LAN, id = null, peer = "203.0.113.$it", at = 1_000L + it)) }
        assertEquals(2, h.entries().size)
        assertEquals("the real approval is still there", Verdict.APPROVED, h.entries().last().verdict)
        assertEquals(1_000, h.entries().first().count)
    }

    @Test
    fun `decisions the user took part in are never merged`() {
        val h = History()
        repeat(3) { h.record(entry(Verdict.DENIED, at = 1_000L + it)) }
        assertEquals(3, h.entries().size)
    }

    @Test
    fun `text from the network is cleaned and bounded`() {
        val h = History()
        h.record(entry(label = "a\nb\u0007" + "x".repeat(500), peer = "1.2.3.4\r\n" + "y".repeat(500)))
        val e = h.entries().single()
        assertTrue(e.label.length <= 80 && e.peer.length <= 64)
        assertFalse(e.label.any { it.isISOControl() })
        assertFalse(e.peer.any { it.isISOControl() })
    }

    @Test
    fun `groups consecutive entries by local day`() {
        val zone = ZoneId.of("America/Los_Angeles")
        fun at(s: String) = java.time.ZonedDateTime.parse(s).toInstant().toEpochMilli()
        val list = listOf(
            entry(at = at("2026-11-12T23:30:00-08:00[America/Los_Angeles]")),
            entry(at = at("2026-11-12T00:05:00-08:00[America/Los_Angeles]")),
            entry(at = at("2026-11-11T23:59:00-08:00[America/Los_Angeles]")),
        )
        val g = History.groupByDay(list, zone)
        assertEquals(listOf(2, 1), g.map { it.second.size })
        assertEquals(java.time.LocalDate.of(2026, 11, 12), g.first().first)
        assertTrue(History.groupByDay(emptyList(), zone).isEmpty())
    }

    @Test
    fun `every approval outcome maps to a verdict`() {
        assertEquals(Verdict.APPROVED, Approval.How.APPROVED.toVerdict())
        assertEquals(Verdict.DENIED, Approval.How.DENIED_IN_APP.toVerdict())
        assertEquals(Verdict.DENIED_NOTIFICATION, Approval.How.DENIED_FROM_NOTIFICATION.toVerdict())
        assertEquals(Verdict.TIMED_OUT, Approval.How.TIMED_OUT.toVerdict())
        assertEquals(Verdict.CANCELLED, Approval.How.CANCELLED.toVerdict())
        assertEquals("unknown is not claimed as anything else", Verdict.CANCELLED, (null as Approval.How?).toVerdict())
    }

    @Test
    fun `the stored codes are unique and stable`() {
        assertEquals(Verdict.entries.size, Verdict.entries.map { it.code }.toSet().size)
        assertEquals(Refusal.entries.size, Refusal.entries.map { it.code }.toSet().size)
        // Renumbering these would reinterpret every phone's existing history.
        assertEquals(listOf("a", "d", "n", "t", "c", "r"), Verdict.entries.map { it.code })
        assertEquals(listOf("k", "c", "l", "g", "q", "w", "h", "b"), Refusal.entries.map { it.code })
    }

    @Test
    fun `the file holds no challenge or signature fields`() {
        val text = History.encode(listOf(entry()))
        assertEquals(2, text.trim().lines().size)
        assertEquals("sudostamp-history 1", text.lines().first())
        assertEquals(7, text.lines()[1].split('\t').size)
    }

    // ---- the description of what a request was for (context-v1@sudostamp)

    private fun b64(s: String) = java.util.Base64.getEncoder().encodeToString(s.toByteArray())

    @Test
    fun `an entry written before descriptions existed still loads, without one`() {
        // Seven fields, exactly as 1.x wrote them (at, verdict, refusal, count, host, label, peer).
        val line = listOf("1700000000000", "a", "-", "1", b64(host), b64("edith"), b64("192.0.2.7")).joinToString("\t")
        val f = File(tmp.root, "old.txt").apply { writeText("sudostamp-history 1\n$line\n") }
        val e = History(f).entries().single()
        assertNull(e.command)
        assertEquals(Verdict.APPROVED, e.verdict)
        assertEquals("edith", e.label)
    }

    @Test
    fun `a description round trips and an entry without one stays seven fields`() {
        val f = File(tmp.root, "c.txt")
        val h = History(f)
        h.record(entry(command = "claude: update the packages \u00e9\u4e2d\uD83D\uDE00"))
        h.record(entry())
        val back = History(f).entries()
        assertEquals(h.entries(), back)
        assertNull(back.first().command)
        assertEquals("claude: update the packages \u00e9\u4e2d\uD83D\uDE00", back.last().command)
        val lines = History.encode(back).trim().lines().drop(1)
        assertEquals(7, lines[0].split('\t').size)
        assertEquals(8, lines[1].split('\t').size)
    }

    @Test
    fun `a stored description is scrubbed and shortened on the way in and on the way out`() {
        val h = History()
        h.record(entry(command = "sudo \u202Ex/pmt/ fr- mr"))
        assertEquals("sudo ?x/pmt/ fr- mr", h.entries().single().command)
        h.record(entry(command = "x".repeat(900)))
        val cut = h.entries().first().command!!
        assertEquals(200, cut.codePointCount(0, cut.length))
        assertTrue(cut.endsWith("\u2026"))
        // A file written by something else gets the same treatment when it is read.
        val line = listOf("1700000000000", "a", "-", "1", b64(host), b64("edith"), b64("p"), b64("a\u001B[31mb\u202Ec")).joinToString("\t")
        val e = History.decode("sudostamp-history 1\n$line\n").single()
        assertEquals("a?[31mb?c", e.command)
        val blank = listOf("1700000000000", "a", "-", "1", b64(host), b64("edith"), b64("p"), b64(" \u00a0 ")).joinToString("\t")
        assertNull(History.decode("sudostamp-history 1\n$blank\n").single().command)
    }

    @Test
    fun `a line with ten fields is skipped`() {
        val line = listOf("1700000000000", "a", "-", "1", b64(host), b64("e"), b64("p"), b64("x"), b64("y"), b64("z")).joinToString("\t")
        assertTrue(History.decode("sudostamp-history 1\n$line\n").isEmpty())
    }

    private fun secret(v: Verdict, name: String, why: String? = null, r: Refusal? = null) =
        HistoryEntry(t++, v, r, host, "build-box", "192.0.2.7", command = why, secret = name)

    @Test
    fun `an approved secret keeps its name and reason, through the file`() {
        val f = File(tmp.root, "h.txt")
        val h = History(f)
        h.record(secret(Verdict.APPROVED, "restic", "weekly backup"))
        h.record(secret(Verdict.APPROVED, "disk"))
        h.record(entry())
        val back = History(f).entries()
        assertEquals(h.entries(), back)
        assertNull("sudo rows stay sudo rows", back[0].secret)
        assertEquals("disk", back[1].secret)
        assertNull(back[1].command)
        assertEquals("restic", back[2].secret)
        assertEquals("weekly backup", back[2].command)
    }

    @Test
    fun `a secret that was not sent leaves no text`() {
        val h = History(File(tmp.root, "h.txt"))
        h.record(secret(Verdict.DENIED, "restic", "weekly backup"))
        h.record(secret(Verdict.TIMED_OUT, "restic", "weekly backup"))
        h.record(secret(Verdict.REFUSED, "restic", "weekly backup", Refusal.BAD_REQUEST))
        h.record(secret(Verdict.APPROVED, "not a name", "x"))
        for (e in h.entries()) {
            assertEquals("", e.secret)
            assertNull(e.command)
        }
    }

    @Test
    fun `a stored secret row that names more than an approval may is skipped`() {
        fun line(v: String, r: String, why: String, name: String) =
            listOf("1700000000000", v, r, "1", b64(host), b64("e"), b64("p"), b64(why), b64(name)).joinToString("\t")
        assertEquals(1, History.decode("sudostamp-history 1\n${line("a", "-", "why", "restic")}\n").size)
        assertEquals(1, History.decode("sudostamp-history 1\n${line("r", "b", "", "")}\n").size)
        for (bad in listOf(line("r", "b", "", "restic"), line("d", "-", "why", ""), line("a", "-", "", "a b")))
            assertTrue(bad, History.decode("sudostamp-history 1\n$bad\n").isEmpty())
    }

    @Test
    fun `refused secrets and refused sudo requests are not merged`() {
        val h = History()
        h.record(refused(Refusal.COOLDOWN))
        h.record(HistoryEntry(t++, Verdict.REFUSED, Refusal.COOLDOWN, host, "edith", "192.0.2.7", secret = ""))
        assertEquals(2, h.entries().size)
    }
}
