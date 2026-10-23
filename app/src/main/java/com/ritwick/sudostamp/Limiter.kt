package com.ritwick.sudostamp

/**
 * Decides when a sign request may NOT be put to the user, even though it names a paired
 * computer's key. The attack is approval fatigue and timing: something that can make the
 * phone ask, again and again or right after a real approval, hoping for a tired or reflexive
 * touch. Refusing never locks anyone out -- the password always works.
 *
 * Keyed by COMPUTER (its key), never by IP address: an address is free to change, so the
 * version-1 cooldown per address was beaten by rotating through IPv6 addresses.
 *
 *   - After an approval, every request is refused for [QUIET_AFTER_APPROVAL_MS]. A request
 *     queued behind a real one would otherwise pop up the moment the first was approved, and
 *     read as "sudo asked twice". (sudo caches the approval, so a real second sudo right after
 *     does not ask.)
 *   - After a denial or timeout, that computer is refused for a while: briefly for a trusted
 *     one (a mistaken Deny can be retried), longer for one never yet approved.
 *   - Across all computers, [GLOBAL_LIMIT] unapproved requests within [GLOBAL_WINDOW_MS]
 *     refuse everything until the oldest of them leaves the window.
 */
class Limiter(private val now: () -> Long = System::currentTimeMillis) {

    companion object {
        const val QUIET_AFTER_APPROVAL_MS = 3_000L
        const val COOLDOWN_TRUSTED_MS = 5_000L
        const val COOLDOWN_PENDING_MS = 60_000L
        const val GLOBAL_LIMIT = 4
        const val GLOBAL_WINDOW_MS = 10 * 60_000L
    }

    private var quietUntil = 0L
    private val until = HashMap<String, Long>()
    private val recent = ArrayDeque<Long>()

    /** Why a request for [hostId] must be refused without asking, or null if it may be asked. */
    @Synchronized
    fun refusal(hostId: String): String? {
        val t = now()
        while (recent.isNotEmpty() && t - recent.first() >= GLOBAL_WINDOW_MS) recent.removeFirst()
        return when {
            t < quietUntil -> "a request was just approved; refusing the next one for a moment"
            recent.size >= GLOBAL_LIMIT -> "too many unapproved requests recently"
            t < (until[hostId] ?: 0L) -> "cooling down after an unapproved request from this computer"
            else -> null
        }
    }

    @Synchronized
    fun approved() {
        quietUntil = now() + QUIET_AFTER_APPROVAL_MS
    }

    /** A request for [hostId] was denied or timed out. [trusted]: approved before. */
    @Synchronized
    fun unapproved(hostId: String, trusted: Boolean) {
        val t = now()
        until[hostId] = t + if (trusted) COOLDOWN_TRUSTED_MS else COOLDOWN_PENDING_MS
        recent.addLast(t)
        while (recent.size > GLOBAL_LIMIT) recent.removeFirst()
    }

    /** Forget [hostId] (it was removed). The map holds paired computers only, so it is small. */
    @Synchronized
    fun forget(hostId: String) {
        until.remove(hostId)
    }
}
