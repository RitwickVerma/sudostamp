package com.ritwick.sudostamp

/**
 * What a computer says a sudo is for, held until the sign request it belongs to arrives.
 *
 * WHY IT EXISTS: pam_rssh signs an opaque 32-byte challenge, so the approval screen could only
 * say "Approve sudo on <computer>?". The host's probe now opens its own short connection right
 * before pam_rssh and sends one description of the command ([AgentProtocol.EXT_CONTEXT]); the
 * phone shows it on the approval for the NEXT sign request from the same client address.
 *
 * ADVISORY, NEVER AUTHORITY: a program running as the user on that computer can send any
 * description. So nothing here may influence whether a request is refused or approved -- it is
 * only ever text next to the fingerprint prompt, labelled as the computer's own claim. A
 * disagreement is surfaced, not resolved: two different descriptions inside the window mean
 * something else is talking, and the screen says so instead of picking one.
 *
 * Pure and clock-injected (callers pass SystemClock.elapsedRealtime(), which counts sleep),
 * so it is JVM-tested. Called from listener threads: every method is synchronized.
 */
class ContextBox(private val ttlMs: Long = TTL_MS, private val maxClients: Int = MAX_CLIENTS) {

    companion object {
        /** From the probe's description to pam_rssh's sign request is well under a second; this is slack. */
        // The probe sends its description a few milliseconds before pam_rssh's request (the local
        // reader, if any, is asked BEFORE the probe): 5 s is ample, and a description left over from
        // a sudo that never asked cannot linger long enough to be pinned on the next one.
        const val TTL_MS = 5_000L
        const val MAX_CLIENTS = 16
    }

    /** What [take] found. [text] is null when [conflicted]: a contested description is never shown. */
    data class Seen(val text: String?, val conflicted: Boolean)

    private class Entry(val text: String, val at: Long, var conflicted: Boolean)

    /** Insertion order = age order, so the first key is the oldest client. */
    private val entries = LinkedHashMap<String, Entry>()

    private fun expired(e: Entry, now: Long) = now - e.at >= ttlMs

    /**
     * Stores [text] for [client]. The first text within the TTL is kept; a DIFFERENT one while
     * it is pending marks the client conflicted (the same text again is just a repeat). The TTL
     * runs from the first text, so repeating cannot keep a description alive.
     */
    @Synchronized
    fun put(client: String, text: String, now: Long) {
        entries.values.removeAll { expired(it, now) }
        val e = entries[client]
        if (e != null) {
            if (e.text != text) e.conflicted = true
            return
        }
        entries[client] = Entry(text, now, false)
        while (entries.size > maxClients) entries.remove(entries.keys.first())
    }

    /** Consumes what [client] has pending: single use, so a description never carries over to a
     *  later request. Null when there is none or it expired. */
    @Synchronized
    fun take(client: String, now: Long): Seen? {
        val e = entries.remove(client) ?: return null
        if (expired(e, now)) return null
        return if (e.conflicted) Seen(null, true) else Seen(e.text, false)
    }
}

/**
 * A command that is one of the host tool's script runs:
 * `sudo [-k] [--] .../sudostamp-run <sha256> <agent> -- <why>`.
 * [why] is free text; it is the agent's own words, so it is as advisory as the rest.
 */
data class Run(val sha: String, val agent: String, val why: String) {
    /** The first 16 hex digits in groups of four, the way the screen shows a script's identity. */
    val shortSha: String get() = sha.take(16).chunked(4).joinToString(" ")
}

private val SHA_RE = Regex("[0-9a-f]{64}")
private val AGENT_RE = Regex("[a-z0-9][a-z0-9._-]{0,31}")

private fun base(token: String) = token.substringAfterLast('/')

/**
 * Reads [command] (sudo's argv joined with single spaces) as a script run, or null for anything
 * else. Exactly: token 0 with basename `sudo`; optionally `-k`; optionally `--`; a token with
 * basename `sudostamp-run`; a lowercase 64-hex sha256; an agent name; the literal `--`; and the
 * rest, kept as it is, as the reason (not empty). Tokens split on single spaces and nothing is
 * collapsed, so a doubled space between those tokens is a no.
 */
fun parseRun(command: String): Run? {
    val t = command.split(' ')
    var i = 0
    if (t.getOrNull(i)?.let(::base) != "sudo") return null
    i++
    if (t.getOrNull(i) == "-k") i++
    if (t.getOrNull(i) == "--") i++
    // The installed runner and nothing else: a `sudostamp-run` anywhere else is somebody's program
    // dressed as an agent's run, and is shown as the command line it is.
    if (t.getOrNull(i) != RUNNER) return null
    i++
    val sha = t.getOrNull(i)?.takeIf { SHA_RE.matches(it) } ?: return null
    i++
    val agent = t.getOrNull(i)?.takeIf { AGENT_RE.matches(it) } ?: return null
    i++
    if (t.getOrNull(i) != "--") return null
    i++
    val why = t.drop(i).joinToString(" ").trim()
    if (why.isEmpty()) return null
    return Run(sha, agent, why)
}

/** One line for a notification or the history: "agent: why" for a script run, else the command. */
fun describeContext(command: String): String =
    parseRun(command)?.let { "${it.agent}: ${it.why} (SHA-256 ${it.sha.take(16)}…)" } ?: command

/** Where the installer puts the agents' runner (tools/install.sh RUNNER). */
const val RUNNER = "/usr/local/sbin/sudostamp-run"
