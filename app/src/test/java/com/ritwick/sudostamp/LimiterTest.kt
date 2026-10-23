package com.ritwick.sudostamp

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/** When a paired computer's request is refused without asking: approval fatigue and timing. */
class LimiterTest {

    private var t = 1_000_000L
    private val l = Limiter { t }

    @Test
    fun `a request right behind an approval is not put to the user`() {
        // The "sudo asked twice" attack: a second request queued behind the real one.
        l.approved()
        assertNotNull(l.refusal("a"))
        assertNotNull("whichever computer it names", l.refusal("b"))
        t += Limiter.QUIET_AFTER_APPROVAL_MS
        assertNull(l.refusal("a"))
    }

    @Test
    fun `a denial cools that computer down - briefly when trusted, longer when new`() {
        l.unapproved("trusted", trusted = true)
        l.unapproved("new", trusted = false)
        assertNotNull(l.refusal("trusted"))
        assertNotNull(l.refusal("new"))
        assertNull("others are unaffected", l.refusal("other"))
        t += Limiter.COOLDOWN_TRUSTED_MS
        assertNull("a mistaken Deny can be retried", l.refusal("trusted"))
        assertNotNull(l.refusal("new"))
        t += Limiter.COOLDOWN_PENDING_MS
        assertNull(l.refusal("new"))
    }

    @Test
    fun `too many unapproved requests overall silence everything for a while`() {
        // Keyed by computer, not IP address: changing addresses does not help, and many
        // computers together are capped too.
        repeat(Limiter.GLOBAL_LIMIT) { l.unapproved("host$it", trusted = true); t += Limiter.COOLDOWN_TRUSTED_MS }
        assertNotNull(l.refusal("fresh"))
        t += Limiter.GLOBAL_WINDOW_MS
        assertNull(l.refusal("fresh"))
    }

    @Test
    fun `forgetting a computer clears its cooldown`() {
        l.unapproved("gone", trusted = false)
        l.forget("gone")
        assertNull(l.refusal("gone"))
    }
}
