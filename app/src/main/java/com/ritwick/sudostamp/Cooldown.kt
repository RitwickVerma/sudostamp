package com.ritwick.sudostamp

/**
 * Silences hosts that keep asking without being approved.
 *
 * The attack this blunts is approval fatigue: anyone on the same network (a café Wi-Fi
 * counts) can make the phone ask "Approve sudo?" again and again, hoping for a tired tap.
 * They cannot approve anything themselves, but they choose when the prompts come.
 *
 * Only hosts that have NEVER been approved are cooled down: after a denial or a timeout,
 * further requests from that address are refused without asking for [windowMs]. A known
 * host (your own machine) is never silenced, so a mistaken Deny never locks you out of
 * retrying -- and the password always works regardless.
 */
class Cooldown(private val windowMs: Long, private val now: () -> Long = System::currentTimeMillis) {

    private val until = HashMap<String, Long>()

    /** True if requests from [host] must be refused without prompting right now. */
    @Synchronized
    fun active(host: String, known: Boolean): Boolean {
        if (known) return false
        val t = until[host] ?: return false
        if (now() >= t) {
            until.remove(host)
            return false
        }
        return true
    }

    /** Records an unapproved request (denied or timed out) from [host]. */
    @Synchronized
    fun unapproved(host: String, known: Boolean) {
        if (known) return
        // Bounded: a LAN can hold many addresses, and this must not grow without limit.
        if (until.size >= MAX_HOSTS) {
            val t = now()
            until.entries.removeAll { it.value <= t }
            if (until.size >= MAX_HOSTS) until.remove(until.minByOrNull { it.value }!!.key)
        }
        until[host] = now() + windowMs
    }

    private companion object {
        const val MAX_HOSTS = 256
    }
}
