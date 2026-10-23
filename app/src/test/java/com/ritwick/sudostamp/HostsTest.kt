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
    fun `ids are only ever ours`() {
        assertTrue(Hosts.validId("0123456789abcdef"))
        assertTrue(Hosts.validId(Hosts.LEGACY_ID))
        assertFalse(Hosts.validId("0123456789ABCDEF"))
        assertFalse(Hosts.validId("0123"))
        assertFalse(Hosts.validId("sudostamp-v1"))
    }
}
