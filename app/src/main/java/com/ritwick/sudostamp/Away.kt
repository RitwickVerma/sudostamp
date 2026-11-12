package com.ritwick.sudostamp

/**
 * Away mode, the pure part: the listener is stopped on purpose, so sudo goes straight to the
 * password, until the user resumes or a timer runs out.
 *
 * It can only ever REDUCE what the phone accepts. Nothing here signs, approves or opens a
 * port: the worst a bug in this file does is leave the listener on (the normal state, where a
 * fingerprint is still needed for everything) or off (the password path).
 *
 * The state is one number, [until], in wall-clock epoch ms: [OFF] (listening), [NEVER] (until
 * resumed), or the time the timer ends. A wall clock, because it must survive a reboot, where
 * elapsedRealtime restarts; the price is that a clock set back lengthens a timer, so a finite
 * [until] is never trusted beyond [MAX_FINITE_MS] from now ([plan] clamps it).
 */
object Away {
    const val OFF = 0L
    const val NEVER = Long.MAX_VALUE
    const val MAX_FINITE_MS = 8 * 3_600_000L

    /** What "Resume automatically" offers. The code is what is stored. */
    enum class Choice(val code: String, val ms: Long?) {
        HOUR("1h", 3_600_000L),
        EIGHT_HOURS("8h", MAX_FINITE_MS),
        NEVER("never", null);

        companion object {
            /** Unknown or missing codes fall back to the shortest: a wrong guess then costs
             *  an hour of password, never a listener left off for good. */
            fun of(code: String?): Choice = entries.firstOrNull { it.code == code } ?: HOUR
        }
    }

    fun until(now: Long, choice: Choice): Long = choice.ms?.let { now + it } ?: NEVER

    /** Away right now? Anything unreadable or in the past is "not away". */
    fun isAway(until: Long, now: Long): Boolean = plan(until, now).away

    /** What the service does when it starts, resumes or is poked: [away] says whether to keep
     *  the listener off; [until] is what to store (OFF once over; a clamped value if the clock
     *  moved); [timerAt] is when to look again, or null for none. */
    data class Plan(val away: Boolean, val until: Long, val timerAt: Long?)

    fun plan(stored: Long, now: Long): Plan = when {
        stored == NEVER -> Plan(true, NEVER, null)
        stored <= OFF -> Plan(false, OFF, null)
        else -> {
            val end = minOf(stored, now + MAX_FINITE_MS)
            if (now >= end) Plan(false, OFF, null) else Plan(true, end, end)
        }
    }

    /** Whole minutes left, rounded up, for "Resumes in 12 min"; null for no end. */
    fun minutesLeft(until: Long, now: Long): Long? =
        if (until == NEVER || until <= OFF) null else ((until - now).coerceAtLeast(0) + 59_999) / 60_000
}

/** The Quick Settings tile: what it shows and what a tap does, as plain data. */
object QuickTile {
    enum class Model { LISTENING, AWAY, OFF }

    enum class Tap { GO_AWAY, RESUME, OPEN_APP }

    /** [listening] is the service's socket; [away] the stored state; [hasHosts] whether any
     *  computer is paired (without one there is nothing to listen for). */
    fun model(hasHosts: Boolean, away: Boolean, listening: Boolean): Model = when {
        away -> Model.AWAY
        hasHosts && listening -> Model.LISTENING
        else -> Model.OFF
    }

    /** OFF means something needs attention, which the app explains and a toggle cannot fix. */
    fun tap(model: Model): Tap = when (model) {
        Model.LISTENING -> Tap.GO_AWAY
        Model.AWAY -> Tap.RESUME
        Model.OFF -> Tap.OPEN_APP
    }
}

/** When the approval screen may be drawn over the lock screen. */
object LockScreen {
    /**
     * Only the approval of a request the user opened from ITS OWN notification, and only while
     * that request is still waiting. Everything else (setup, history, computers, pairing, the
     * result) must stay behind the keyguard.
     *
     * Safe because it shows the computer's name and nothing else, and approving still needs a
     * fresh strong biometric for the Keystore key on every use: the lock screen is no part of
     * that gate, so showing the prompt there does not move it.
     */
    fun overKeyguard(onApprovalScreen: Boolean, requestId: Long, notifiedId: Long, pending: Boolean): Boolean =
        onApprovalScreen && pending && requestId >= 0 && requestId == notifiedId

    /** Draw a screen at all? A locked device shows only what [overKeyguard] allows. */
    fun mayDraw(deviceLocked: Boolean, overKeyguard: Boolean): Boolean = !deviceLocked || overKeyguard
}
