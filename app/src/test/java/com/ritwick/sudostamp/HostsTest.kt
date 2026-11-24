package com.ritwick.sudostamp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The stored list of paired computers: it must round-trip any label, and a damaged line must
 *  not take the others with it. */
class HostsTest {

    private val a = Host("0123456789abcdef", "edith", 1_700_000_000_000L, true, "192.168.1.7")
    private val b = Host("fedcba9876543210", "tab\there\nnewline é", 1L, false, "[fd00::9]")

    @Test
    fun `round-trips, including labels with tabs and newlines`() {
        assertEquals(listOf(a, b), Hosts.decode(Hosts.encode(listOf(a, b))))
        assertEquals(emptyList<Host>(), Hosts.decode(Hosts.encode(emptyList())))
    }

    @Test
    fun `damaged or foreign lines are skipped, not fatal`() {
        val good = Hosts.encode(listOf(a))
        val stored = listOf("garbage", "../../etc\t1\t1\tZQ==\tZQ==", "0123456789abcdeg\t1\t1\tZQ==\tZQ==",
            "fedcba9876543210\tnot-a-number\t1\tZQ==\tZQ==", good).joinToString("\n")
        assertEquals(listOf(a), Hosts.decode(stored))
    }

    @Test
    fun `one host key is one computer - pairing again replaces the older entry`() {
        // The same H paired again (setup run twice, or a key file copied to a second machine):
        // the older entry goes, so a stolen or shared H cannot keep asking under the old pairing.
        val h1 = a.copy(hostKey = "BAAA")
        val other = b.copy(hostKey = "BBBB")
        val legacy = Host("1111111111111111", "old", 2L, true, "x")
        val again = Host("2222222222222222", "edith", 3L, false, "192.0.2.9", "BAAA")
        val (list, gone) = Hosts.adding(listOf(h1, other, legacy), again)
        assertEquals(listOf(other, legacy, again), list)
        assertEquals(listOf(h1.id), gone)
        // No host key: nothing to compare, nothing replaced but the same id.
        val (list2, gone2) = Hosts.adding(listOf(legacy, other), legacy.copy(label = "renamed"))
        assertEquals(listOf(other, legacy.copy(label = "renamed")), list2)
        assertEquals(emptyList<String>(), gone2)
    }

    @Test
    fun `ids are only ever ours`() {
        assertTrue(Hosts.validId("0123456789abcdef"))
        assertTrue(Hosts.validId(Hosts.LEGACY_ID))
        assertFalse(Hosts.validId("0123456789ABCDEF"))
        assertFalse(Hosts.validId("0123"))
        assertFalse(Hosts.validId("sudostamp-v1"))
    }
}
