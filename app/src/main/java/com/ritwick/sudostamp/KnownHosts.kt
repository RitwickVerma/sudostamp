package com.ritwick.sudostamp

import android.content.Context

/**
 * Hosts that have had a request approved on this phone before.
 *
 * The approval screen flags a request from any other host. The signature itself is safe to
 * hand out (pam_rssh's challenge is fresh each time), so the real risk is the user approving
 * a request they did not start, timed to land when they expect their own. "First request
 * from this host" is the one cue that tells those apart without reading an IP address.
 *
 * Local app data only: excluded from backup and device transfer like everything else here.
 */
object KnownHosts {

    private const val PREFS = "known-hosts"
    private const val KEY = "hosts"

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun isKnown(ctx: Context, host: String): Boolean =
        host in prefs(ctx).getStringSet(KEY, emptySet())!!

    /** Records [host] as approved. True if it was not known before. */
    @Synchronized
    fun remember(ctx: Context, host: String): Boolean {
        val hosts = prefs(ctx).getStringSet(KEY, emptySet())!!
        if (host in hosts) return false
        prefs(ctx).edit().putStringSet(KEY, hosts + host).apply()
        return true
    }

    /** Forgets every host -- part of a reset, since a new key starts a new trust history. */
    fun clear(ctx: Context) {
        prefs(ctx).edit().clear().apply()
    }
}
