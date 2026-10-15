package com.ritwick.sudostamp

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Approval-fatigue limiting: unknown hosts that keep asking are silenced for a while. */
class CooldownTest {

    private var t = 1_000L
    private val c = Cooldown(30_000) { t }

    @Test
    fun `an unknown host is silenced after an unapproved request, then released`() {
        assertFalse(c.active("10.0.0.9", known = false))
        c.unapproved("10.0.0.9", known = false)
        assertTrue(c.active("10.0.0.9", known = false))
        t += 29_999
        assertTrue(c.active("10.0.0.9", known = false))
        t += 1
        assertFalse("released after the window", c.active("10.0.0.9", known = false))
    }

    @Test
    fun `a known host is never silenced`() {
        c.unapproved("10.0.0.2", known = true)
        assertFalse(c.active("10.0.0.2", known = true))
        // Even a cooldown recorded while it was still unknown does not block it once known.
        c.unapproved("10.0.0.3", known = false)
        assertFalse(c.active("10.0.0.3", known = true))
    }

    @Test
    fun `other hosts are unaffected`() {
        c.unapproved("10.0.0.9", known = false)
        assertFalse(c.active("10.0.0.10", known = false))
    }

    @Test
    fun `memory stays bounded under an address flood`() {
        repeat(10_000) { c.unapproved("10.%d.%d.%d".format(it shr 16, (it shr 8) and 255, it and 255), known = false) }
        // The most recent are still silenced: the bound evicts the oldest entries.
        assertTrue(c.active("10.0.39.15", known = false))
    }
}
