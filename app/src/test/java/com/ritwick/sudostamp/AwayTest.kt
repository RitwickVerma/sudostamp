package com.ritwick.sudostamp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Away mode's decisions, the tile's model and the lock screen policy: all pure. */
class AwayTest {

    private val now = 1_800_000_000_000L
    private val hour = 3_600_000L

    @Test
    fun `away-until arithmetic for each choice`() {
        assertEquals(now + hour, Away.until(now, Away.Choice.HOUR))
        assertEquals(now + 8 * hour, Away.until(now, Away.Choice.EIGHT_HOURS))
        assertEquals(Away.NEVER, Away.until(now, Away.Choice.NEVER))
    }

    @Test
    fun `not away by default and once the end has passed`() {
        assertFalse(Away.isAway(Away.OFF, now))
        assertFalse(Away.isAway(now - 1, now))
        assertFalse("exactly at the end is over", Away.isAway(now, now))
        assertTrue(Away.isAway(now + 1, now))
        assertTrue(Away.isAway(Away.NEVER, now))
    }

    @Test
    fun `garbage values mean not away`() {
        assertFalse(Away.isAway(-5, now))
        assertEquals(Away.Plan(false, Away.OFF, null), Away.plan(-5, now))
    }

    @Test
    fun `a reboot during a timer keeps the phone away and re-arms the timer`() {
        val end = now + 30 * 60_000
        assertEquals(Away.Plan(true, end, end), Away.plan(end, now))
    }

    @Test
    fun `a reboot after the timer ran out comes back listening and clears it`() {
        assertEquals(Away.Plan(false, Away.OFF, null), Away.plan(now - 60_000, now))
    }

    @Test
    fun `never survives a reboot with no timer`() {
        assertEquals(Away.Plan(true, Away.NEVER, null), Away.plan(Away.NEVER, now))
    }

    @Test
    fun `a clock set back cannot stretch a timer beyond the longest choice`() {
        // Stored when the clock said "now"; later the clock reads a week earlier.
        val stored = now + 8 * hour
        val earlier = now - 7 * 24 * hour
        val p = Away.plan(stored, earlier)
        assertTrue(p.away)
        assertEquals(earlier + Away.MAX_FINITE_MS, p.until)
        assertEquals(p.until, p.timerAt)
    }

    @Test
    fun `an Away that only ever reduces - nothing here turns listening on by itself`() {
        // plan() never reports away=false for NEVER or a future time: only the user's Resume
        // (or a timer passing) ends it, so a bug cannot silently resume.
        for (offset in listOf(1L, 1_000L, hour, 8 * hour)) assertTrue(Away.plan(now + offset, now).away)
    }

    @Test
    fun `an unknown stored choice falls back to one hour`() {
        assertEquals(Away.Choice.HOUR, Away.Choice.of(null))
        assertEquals(Away.Choice.HOUR, Away.Choice.of("forever"))
        assertEquals(Away.Choice.NEVER, Away.Choice.of("never"))
        assertEquals(Away.Choice.EIGHT_HOURS, Away.Choice.of("8h"))
    }

    @Test
    fun `minutes left round up and never go negative`() {
        assertEquals(1L, Away.minutesLeft(now + 1, now))
        assertEquals(60L, Away.minutesLeft(now + hour, now))
        assertEquals(0L, Away.minutesLeft(now - 5, now))
        assertNull(Away.minutesLeft(Away.NEVER, now))
        assertNull(Away.minutesLeft(Away.OFF, now))
    }

    // ---- the tile

    @Test
    fun `tile model and tap`() {
        assertEquals(QuickTile.Model.LISTENING, QuickTile.model(hasHosts = true, away = false, listening = true))
        assertEquals(QuickTile.Model.AWAY, QuickTile.model(true, true, false))
        assertEquals("away wins even if the socket is still closing", QuickTile.Model.AWAY, QuickTile.model(true, true, true))
        assertEquals(QuickTile.Model.OFF, QuickTile.model(true, false, false))
        assertEquals("nothing paired: nothing to listen for", QuickTile.Model.OFF, QuickTile.model(false, false, true))

        assertEquals(QuickTile.Tap.GO_AWAY, QuickTile.tap(QuickTile.Model.LISTENING))
        assertEquals(QuickTile.Tap.RESUME, QuickTile.tap(QuickTile.Model.AWAY))
        assertEquals("a toggle cannot fix an Off tile", QuickTile.Tap.OPEN_APP, QuickTile.tap(QuickTile.Model.OFF))
    }

    // ---- the lock screen

    @Test
    fun `only the notified pending request's approval may sit over the keyguard`() {
        assertTrue(LockScreen.overKeyguard(true, 7, 7, true))
        assertFalse("setup, history, pairing, result", LockScreen.overKeyguard(false, 7, 7, true))
        assertFalse("a request that was not the one tapped", LockScreen.overKeyguard(true, 8, 7, true))
        assertFalse("once resolved", LockScreen.overKeyguard(true, 7, 7, false))
        assertFalse("no notification at all", LockScreen.overKeyguard(true, 7, -1, true))
        assertFalse(LockScreen.overKeyguard(true, -1, -1, true))
    }

    @Test
    fun `a locked phone draws only what is allowed over the keyguard`() {
        assertTrue(LockScreen.mayDraw(deviceLocked = false, overKeyguard = false))
        assertTrue(LockScreen.mayDraw(false, true))
        assertTrue(LockScreen.mayDraw(true, true))
        assertFalse(LockScreen.mayDraw(true, false))
    }
}
