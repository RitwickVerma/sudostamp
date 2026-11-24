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
    /** Pairing v3: the computer's host key (65-byte P-256 point), Base64. Null for a computer
     *  paired without one: it gets sudo, and every secret request from it is refused unshown.
     *  A String, not a ByteArray, so Host stays a value (data-class equality). */
    val hostKey: String? = null,
    /** The address its last approved request came from; empty until one is approved. With
     *  [pairedFrom], the addresses a request in its name is expected from ([Hosts.expectedFrom]). */
    val seenFrom: String = "",
) {
    /** [hostKey] as bytes, or null when there is none or it is not a P-256 point. */
    fun hostKeyBytes(): ByteArray? = hostKey?.let { k ->
        runCatching { Base64.getDecoder().decode(k).also { Hpke.publicKey(it) } }.getOrNull()
    }
}

object Hosts {

    /** The single key of versions before 1.4, shared by every computer paired then. */
    const val LEGACY_ID = "v1"

    private const val PREFS = "hosts"
    private const val KEY = "hosts-v2"

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    @Synchronized
    fun all(ctx: Context): List<Host> = decode(prefs(ctx).getString(KEY, "") ?: "")

    fun byId(ctx: Context, id: String): Host? = all(ctx).firstOrNull { it.id == id }

    /** Adds [h]; an older entry with the same host key is removed, its Keystore key deleted. */
    @Synchronized
    fun add(ctx: Context, h: Host) {
        val (list, gone) = adding(all(ctx), h)
        gone.forEach { runCatching { Keys.delete(Keys.aliasFor(it)) } }
        save(ctx, list)
    }

    /**
     * [list] with [h] added, and the ids of the entries it replaces. One host key is one
     * computer: the same H paired again (setup run twice, or the key file copied to another
     * machine) replaces the older entry, so that entry's K cannot go on asking in its name.
     */
    fun adding(list: List<Host>, h: Host): Pair<List<Host>, List<String>> {
        val gone = list.filter { it.id != h.id && h.hostKey != null && it.hostKey == h.hostKey }.map { it.id }
        return Pair(list.filter { it.id != h.id && it.id !in gone } + h, gone)
    }

    /** A request from [id], sent from [client], was approved: trusts it and records [client].
     *  True if it was pending. */
    @Synchronized
    fun approvedFrom(ctx: Context, id: String, client: String): Boolean {
        val (list, wasPending) = approved(all(ctx), id, client)
        save(ctx, list)
        return wasPending
    }

    /** [list] after an approval for [id] from [client], and whether [id] was pending. */
    fun approved(list: List<Host>, id: String, client: String): Pair<List<Host>, Boolean> {
        val h = list.firstOrNull { it.id == id } ?: return Pair(list, false)
        return Pair(list.map { if (it.id == id) it.copy(confirmed = true, seenFrom = client) else it }, !h.confirmed)
    }

    /**
     * Null when a request in [h]'s name from [client] comes from an address that computer is
     * known by (the one it paired from, or its last approved request's); otherwise that
     * address, to show beside [client]. Anything on the LAN can learn a paired computer's key
     * (the phone lists them) and ask in its name, so the address is the one hint the person
     * has. Advisory, never a refusal: a computer that changed address must still get sudo.
     * The pre-1.4 entry has no address and carries its own warning.
     */
    fun expectedFrom(h: Host, client: String): String? = when {
        h.pairedFrom.isEmpty() && h.seenFrom.isEmpty() -> null
        client == h.pairedFrom || client == h.seenFrom -> null
        else -> h.seenFrom.ifEmpty { h.pairedFrom }
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
        ).plus(
            if (h.seenFrom.isEmpty()) listOfNotNull(h.hostKey)
            else listOf(h.hostKey ?: "", b64e.encodeToString(h.seenFrom.toByteArray()))
        ).joinToString("\t")
    }

    /** Lines that do not parse are skipped: a damaged entry must not take the others with it.
     *  Five fields (paired before 2.0, or without a host key), six (the host key, Base64) or
     *  seven (the host key or empty, then the last approved address, Base64). */
    fun decode(s: String): List<Host> = s.lineSequence().mapNotNull { line ->
        val f = line.split('\t')
        if (f.size !in 5..7 || !validId(f[0])) return@mapNotNull null
        runCatching {
            Host(f[0], String(b64d.decode(f[3])), f[1].toLong(), f[2] == "1", String(b64d.decode(f[4])),
                f.getOrNull(5)?.takeIf { it.isNotEmpty() }, f.getOrNull(6)?.let { String(b64d.decode(it)) } ?: "")
        }.getOrNull()
    }.toList()

    /** Ids are ours (random hex, or [LEGACY_ID]); anything else is not an entry we wrote. */
    fun validId(id: String) = id == LEGACY_ID || (id.length == 16 && id.all { it in '0'..'9' || it in 'a'..'f' })
}
