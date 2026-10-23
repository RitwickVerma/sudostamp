package com.ritwick.sudostamp

import java.security.Signature
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * One sign request waiting on the user. It resolves EXACTLY ONCE: approved with a
 * signature, or denied. The first resolution wins and every later one is refused.
 *
 * WHY ONCE: the listener thread gives up after a timeout while the biometric prompt can
 * still be on screen. With separate "approved" and "signature" flags, a fingerprint that
 * landed after the timeout set them anyway -- the app flashed "Approved" and closed while
 * the agent had already answered FAILURE and sudo was denied. A single atomic outcome
 * makes "the agent sent this signature" and "the UI says approved" the same fact.
 */
class Approval(
    /** Unique per request: the notification's buttons name the request they were posted for. */
    val id: Long,
    val signer: Signature,
    val data: ByteArray,
    /** The paired computer whose key is asked for: its id and name ([Host]). */
    val hostId: String,
    val label: String,
    /** False while that computer has never had a request approved: flagged on screen. */
    val trusted: Boolean,
    /** Remote address that asked. Shown under the name, for the record. */
    val client: String,
    /** When the request arrived (epoch ms). */
    val arrivedAt: Long,
) {
    private val outcome = CompletableFuture<ByteArray?>()

    /** Delivers [signatureDer]. False if the request was already resolved: the signature
     *  then goes nowhere, and the caller must not claim success. */
    fun approve(signatureDer: ByteArray): Boolean = outcome.complete(signatureDer)

    /** Denies. False if the request was already resolved. */
    fun deny(): Boolean = outcome.complete(null)

    val isResolved: Boolean get() = outcome.isDone

    /**
     * Blocks up to [timeoutMs] for the user. Returns the DER signature, or null for a
     * denial, timeout or interrupt. A timeout first resolves the request as denied, so a
     * fingerprint arriving a moment later is refused by [approve] -- and one that won the
     * race just before is honoured, because its signature is what getNow returns.
     */
    fun await(timeoutMs: Long): ByteArray? {
        try {
            return outcome.get(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            // fall through: deny, unless the user beat us to it
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        deny()
        return outcome.getNow(null)
    }
}
