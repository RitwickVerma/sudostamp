package com.ritwick.sudostamp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.Signature
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * The approval handshake between the listener thread and the biometric prompt.
 *
 * The bug this guards against: a fingerprint landing after the listener had timed out was
 * still recorded as "approved". The app said Approved and closed, while the agent had
 * already answered FAILURE and sudo was denied. Whatever the UI reports must be what the
 * agent sent.
 */
class ApprovalTest {

    private val sig = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)

    private fun approval() =
        Approval(1L, Signature.getInstance("SHA256withECDSA"), ByteArray(32), "0123456789abcdef", "edith", true, "192.0.2.1", 0L)

    @Test
    fun `approval before the deadline delivers the signature`() {
        val a = approval()
        assertTrue(a.approve(sig))
        assertArrayEquals(sig, a.await(1_000))
    }

    @Test
    fun `a timeout denies, and a late approval is refused`() {
        val a = approval()
        assertNull("timed out", a.await(10))
        assertTrue(a.isResolved)
        assertFalse("late fingerprint must not report success", a.approve(sig))
    }

    @Test
    fun `deny then approve keeps the denial`() {
        val a = approval()
        assertTrue(a.deny())
        assertFalse(a.approve(sig))
        assertNull(a.await(1_000))
    }

    @Test
    fun `approve then deny keeps the approval`() {
        // The listener's cleanup denies unconditionally once await returns; that must be a
        // no-op after a real approval, not a retraction of it.
        val a = approval()
        assertTrue(a.approve(sig))
        assertFalse(a.deny())
        assertArrayEquals(sig, a.await(1_000))
    }

    @Test
    fun `an approval from another thread wakes the waiter`() {
        val a = approval()
        val started = CountDownLatch(1)
        val t = thread {
            started.countDown()
            Thread.sleep(50)
            a.approve(sig)
        }
        started.await(1, TimeUnit.SECONDS)
        assertArrayEquals(sig, a.await(5_000))
        t.join()
    }

    @Test
    fun `an interrupted wait denies`() {
        val a = approval()
        Thread.currentThread().interrupt()
        assertNull(a.await(5_000))
        assertTrue("interrupt flag preserved", Thread.interrupted())
        assertFalse(a.approve(sig))
    }
}
