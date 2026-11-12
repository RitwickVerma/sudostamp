package com.ritwick.sudostamp

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Away mode's storage and the glue around it; the decisions are [Away]'s.
 *
 * Away stops the listener, not the service: the foreground notification stays, because it is
 * what carries the Resume button, and the service is what a timer, the Quick Settings tile and
 * a reboot all talk to. The state is in a private preference, so it survives a reboot and a
 * killed process alike ([StartReceiver] starts the service, which reads it).
 *
 * THE TIMER needs no permission. Three layers, each enough on its own for the next look:
 *   - the service posts a Handler delay (exact, while the phone is awake);
 *   - an INEXACT AlarmManager alarm (setAndAllowWhileIdle: no SCHEDULE_EXACT_ALARM) delivers
 *     [ACTION_TIMER] to [StartReceiver];
 *   - and every start, resume of the app and tap on the tile re-reads the stored end time.
 * If all of them are late, the cost is a few more minutes on the password, never a bypass.
 */
object AwayControl {
    private const val PREFS = "away"
    private const val K_UNTIL = "until"
    private const val K_CHOICE = "choice"

    /** Delivered by the alarm to [StartReceiver]. */
    const val ACTION_TIMER = "com.ritwick.sudostamp.AWAY_TIMER"

    // commit(), not apply(): the service re-reads Away the moment it is poked, and Away must survive
    // an immediate reboot. A write still in flight could resume a listener the user just stopped.
    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** The stored end, or "not away" when it cannot be read. */
    private fun stored(ctx: Context): Long = runCatching { prefs(ctx).getLong(K_UNTIL, Away.OFF) }.getOrDefault(Away.OFF)

    /** The last "resume automatically" choice: what the tile uses. */
    fun choice(ctx: Context): Away.Choice = Away.Choice.of(runCatching { prefs(ctx).getString(K_CHOICE, null) }.getOrNull())

    /**
     * The plan for right now, persisting what it decided (an ended timer is cleared, a
     * clock-skewed one clamped) and arming or cancelling the alarm to match.
     */
    @Synchronized
    fun plan(ctx: Context, now: Long = System.currentTimeMillis()): Away.Plan {
        val before = stored(ctx)
        val p = Away.plan(before, now)
        if (p.until != before) prefs(ctx).edit().putLong(K_UNTIL, p.until).commit()
        arm(ctx, p.timerAt)
        return p
    }

    /** For screens: is it away, and until when ([Away.OFF] when not)? Does not write. */
    fun view(ctx: Context, now: Long = System.currentTimeMillis()): Away.Plan = Away.plan(stored(ctx), now)

    /** Goes away, for good or until a timer. Remembers [choice] for the tile. */
    fun enter(ctx: Context, choice: Away.Choice) {
        synchronized(this) {
            prefs(ctx).edit().putLong(K_UNTIL, Away.until(System.currentTimeMillis(), choice))
                .putString(K_CHOICE, choice.code).commit()
        }
        poke(ctx)
    }

    /** Back to listening. */
    fun resume(ctx: Context) {
        clear(ctx)
        poke(ctx)
    }

    /** [resume] without waking the service: for the service itself. */
    @Synchronized
    fun clear(ctx: Context) {
        prefs(ctx).edit().putLong(K_UNTIL, Away.OFF).commit()
        arm(ctx, null)
    }

    /** Look at the stored end time now; wake the service only if the timer has run out. */
    fun tick(ctx: Context) {
        val s = stored(ctx)
        if (s != Away.OFF && !Away.plan(s, System.currentTimeMillis()).away) {
            Log.i(AgentService.TAG, "away: timer ended, resuming")
            plan(ctx)
            poke(ctx)
        }
    }

    /** Asks the service to re-read the state: starts it if it is not running. A running
     *  foreground service may be sent a plain startService from the background; starting a
     *  stopped one needs a foreground start, which the OS can refuse from the background. */
    fun poke(ctx: Context) {
        val i = Intent(ctx, AgentService::class.java)
        try {
            if (AgentService.alive) ctx.startService(i) else ctx.startForegroundService(i)
        } catch (e: Exception) {
            Log.w(AgentService.TAG, "away: could not reach the listener service: ${e.message}")
        }
    }

    private fun arm(ctx: Context, at: Long?) {
        val am = ctx.getSystemService(AlarmManager::class.java) ?: return
        val pi = PendingIntent.getBroadcast(
            ctx, 3, Intent(ctx, StartReceiver::class.java).setAction(ACTION_TIMER),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        runCatching {
            if (at == null) am.cancel(pi) else am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, pi)
        }.onFailure { Log.w(AgentService.TAG, "away: cannot set the alarm: ${it.message}") }
    }
}
