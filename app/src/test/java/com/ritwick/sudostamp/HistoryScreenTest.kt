package com.ritwick.sudostamp

import org.junit.Assert.assertEquals
import org.junit.Test

class HistoryScreenTest {
    private fun e(v: Verdict, secret: String?) =
        HistoryEntry(0L, v, null, "0000000000000001", "pc", "10.0.0.2", secret = secret)

    @Test
    fun `a secret row that was not answered never talks about signatures or the sensor`() {
        assertEquals(R.string.verdict_secret_denied_detail, HistoryScreen.detail(e(Verdict.DENIED, "")))
        assertEquals(R.string.verdict_secret_denied_notification_detail,
            HistoryScreen.detail(e(Verdict.DENIED_NOTIFICATION, "")))
        assertEquals(R.string.verdict_secret_timed_out_detail, HistoryScreen.detail(e(Verdict.TIMED_OUT, "")))
        assertEquals(R.string.verdict_secret_sent_detail, HistoryScreen.detail(e(Verdict.APPROVED, "restic")))
    }

    @Test
    fun `sudo rows keep their wording`() {
        assertEquals(R.string.verdict_denied_detail, HistoryScreen.detail(e(Verdict.DENIED, null)))
        assertEquals(R.string.verdict_timed_out_detail, HistoryScreen.detail(e(Verdict.TIMED_OUT, null)))
    }
}
