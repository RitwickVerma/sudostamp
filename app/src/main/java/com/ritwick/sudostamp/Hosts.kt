package com.ritwick.sudostamp

import android.content.Context
import java.util.Base64

/**
 * The computers paired with this phone, each with its OWN Keystore key (alias from
 * [Keys.aliasFor]).
 *
 * Why one key per computer: with a single key, a signature made for one computer verified on
 * every other, and the approval screen could only name the requester by IP address -- which
 * anyone on the network can use. Now a sign request names a key, the key names the computer,
 * and the approval screen shows that computer's name. A request relayed from elsewhere either
 * carries its own computer's key (and so its own name) or is refused.
 *
 * PENDING until first approved. Pairing proves which key the computer pinned, not who was
 * sitting at it (see [PairingSession]). So a freshly paired computer is flagged on its first
 * request, and becomes trusted the moment the person approves one. Unknown keys are refused
 * without ever reaching the screen.
 *
 * Local app data only: excluded from backup and device transfer like everything else here.
 */
data class Host(
    val id: String,
    /** The name the computer gave when pairing (display text only). */
    val label: String,
    val pairedAt: Long,
    /** False until a request from this computer has been approved. */
    val confirmed: Boolean,
    /** The address it paired from, for the record. */
    val pairedFrom: String,
)

object Hosts {

    /** The single key of versions before 1.4, shared by every computer paired then. */
    const val LEGACY_ID = "v1"

    private const val PREFS = "hosts"
    private const val KEY = "hosts-v2"

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    @Synchronized
    fun all(ctx: Context): List<Host> = decode(prefs(ctx).getString(KEY, "") ?: "")

    fun byId(ctx: Context, id: String): Host? = all(ctx).firstOrNull { it.id == id }

    @Synchronized
    fun add(ctx: Context, h: Host) = save(ctx, all(ctx).filter { it.id != h.id } + h)

    /** Marks [id] trusted. True if it was pending. */
    @Synchronized
    fun confirm(ctx: Context, id: String): Boolean {
        val list = all(ctx)
        val h = list.firstOrNull { it.id == id } ?: return false
        if (h.confirmed) return false
        save(ctx, list.map { if (it.id == id) it.copy(confirmed = true) else it })
        return true
    }

    /** Forgets [id] and deletes its key: that computer's sudo falls back to the password. */
    @Synchronized
    fun remove(ctx: Context, id: String) {
        runCatching { Keys.delete(Keys.aliasFor(id)) }
        save(ctx, all(ctx).filter { it.id != id })
    }

    /**
     * Brings the stored list in line with the Keystore, once per process start:
     *   - the pre-1.4 key, if present, becomes one (trusted) entry, so an update keeps working;
     *   - a key with no entry (a pairing cut off by a crash) is deleted;
     *   - an entry whose key is gone (the user cleared the Keystore) is dropped.
     */
    @Synchronized
    fun reconcile(ctx: Context) {
        var list = all(ctx)
        if (Keys.exists(Keys.aliasFor(LEGACY_ID)) && list.none { it.id == LEGACY_ID }) {
            list = list + Host(LEGACY_ID, "", 0L, true, "")
        }
        val known = list.map { Keys.aliasFor(it.id) }.toSet()
        Keys.pairingAliases().filter { it !in known }.forEach { runCatching { Keys.delete(it) } }
        list = list.filter { Keys.exists(Keys.aliasFor(it.id)) }
        save(ctx, list)
    }

    private fun save(ctx: Context, list: List<Host>) {
        prefs(ctx).edit().putString(KEY, encode(list)).apply()
    }

    // ------------------------------------------------------------ storage format
    // One line per computer, tab-separated; the free-text fields Base64-encoded so no label can
    // break the format. Plain Kotlin, so it is unit-tested without Android.

    private val b64e = Base64.getEncoder()
    private val b64d = Base64.getDecoder()

    fun encode(list: List<Host>): String = list.joinToString("\n") { h ->
        listOf(
            h.id, h.pairedAt.toString(), if (h.confirmed) "1" else "0",
            b64e.encodeToString(h.label.toByteArray()), b64e.encodeToString(h.pairedFrom.toByteArray()),
        ).joinToString("\t")
    }

    /** Lines that do not parse are skipped: a damaged entry must not take the others with it. */
    fun decode(s: String): List<Host> = s.lineSequence().mapNotNull { line ->
        val f = line.split('\t')
        if (f.size != 5 || !validId(f[0])) return@mapNotNull null
        runCatching {
            Host(f[0], String(b64d.decode(f[3])), f[1].toLong(), f[2] == "1", String(b64d.decode(f[4])))
        }.getOrNull()
    }.toList()

    /** Ids are ours (random hex, or [LEGACY_ID]); anything else is not an entry we wrote. */
    fun validId(id: String) = id == LEGACY_ID || (id.length == 16 && id.all { it in '0'..'9' || it in 'a'..'f' })
}
