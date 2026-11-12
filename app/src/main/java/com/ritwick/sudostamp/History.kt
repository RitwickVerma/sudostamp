package com.ritwick.sudostamp

import android.content.Context
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.util.Base64

/** How the service decided one request. Codes are stored in the file: never renumber them. */
enum class Verdict(val code: String) {
    APPROVED("a"),
    /** The Deny button or the system sheet's Deny/Back, in the app. */
    DENIED("d"),
    /** Deny on the notification: rejected without opening the app. */
    DENIED_NOTIFICATION("n"),
    /** Nobody touched the sensor within the approval window. */
    TIMED_OUT("t"),
    /** Dropped while waiting: the listener stopped, or Away began. */
    CANCELLED("c"),
    /** Never shown to the user: the request failed one of the agent's own checks. */
    REFUSED("r"),
}

/** What the history calls each way an [Approval] can end. */
fun Approval.How?.toVerdict(): Verdict = when (this) {
    Approval.How.APPROVED -> Verdict.APPROVED
    Approval.How.DENIED_IN_APP -> Verdict.DENIED
    Approval.How.DENIED_FROM_NOTIFICATION -> Verdict.DENIED_NOTIFICATION
    Approval.How.TIMED_OUT -> Verdict.TIMED_OUT
    Approval.How.CANCELLED, null -> Verdict.CANCELLED
}

/** Why a request was refused unprompted. Codes are stored in the file: never renumber them. */
enum class Refusal(val code: String) {
    /** A key this phone did not make for any paired computer. */
    UNKNOWN_KEY("k"),
    /** A paired computer's key, but not asked to sign a 32-byte pam_rssh challenge. */
    NOT_A_CHALLENGE("c"),
    /** The peer is not on the Wi-Fi or Ethernet subnet the connection arrived on. */
    OUTSIDE_LAN("l"),
    /** Too many unapproved requests overall ([Limiter.GLOBAL_LIMIT]). */
    RATE_LIMITED("g"),
    /** Within [Limiter.QUIET_AFTER_APPROVAL_MS] of an approval. */
    AFTER_APPROVAL("q"),
    /** That computer was just denied or timed out ([Limiter]). */
    COOLDOWN("w"),
}

/**
 * One decided request. Deliberately no challenge bytes, no signature, no key blob: a log of who
 * asked and what was decided, nothing that could be replayed or that identifies a key.
 *
 * [label] is the computer's name as paired, or "" for a peer that is not paired (shown as
 * "unknown device"); [hostId] is null then. [count] > 1 only for coalesced refusals (see
 * [History.record]); [at] is then the latest of them.
 */
data class HistoryEntry(
    val at: Long,
    val verdict: Verdict,
    val refusal: Refusal?,
    val hostId: String?,
    val label: String,
    val peer: String,
    val count: Int = 1,
)

/**
 * The last [MAX] request outcomes, newest first, kept in one private file.
 *
 * WHY it exists: the refusals are decided without ever reaching the screen, so without this the
 * user cannot learn that something on the LAN keeps asking with a key that is not theirs. The
 * approvals are in it too, so a request the user does not remember approving stands out.
 *
 * It is best-effort and never on the request path: any I/O or format problem means "start empty",
 * and a failed write loses the entry, never the request. Plain java.io, so it is JVM-tested.
 * Excluded from backup and device transfer with the rest of the app's files
 * (res/xml/data_extraction_rules.xml, allowBackup=false).
 *
 * Format v1, text, newline-separated: a header `sudostamp-history 1`, then one entry per line,
 * tab-separated: at, verdict code, refusal code or `-`, count, then Base64 of host id, label and
 * peer (so no text can break a line). A line that does not parse is skipped; a missing, oversized
 * or newer-versioned file reads as empty.
 */
class History(private val file: File? = null, private val max: Int = MAX) {

    companion object {
        const val MAX = 100
        const val VERSION = 1
        private const val HEADER = "sudostamp-history"

        /** 100 entries are ~15 KB. Anything far beyond that is not ours; do not read it. */
        private const val MAX_FILE_BYTES = 256 * 1024
        private const val MAX_LABEL = 80
        private const val MAX_PEER = 64

        /** Identical refusals this close together become one entry with a count, so a client
         *  hammering the port cannot push everything real out of the last 100. */
        const val COALESCE_WINDOW_MS = 10 * 60_000L

        private val b64e = Base64.getEncoder()
        private val b64d = Base64.getDecoder()

        fun encode(list: List<HistoryEntry>): String =
            (listOf("$HEADER $VERSION") + list.map { e ->
                listOf(
                    e.at.toString(), e.verdict.code, e.refusal?.code ?: "-", e.count.toString(),
                    b64e.encodeToString((e.hostId ?: "").toByteArray()),
                    b64e.encodeToString(e.label.toByteArray()),
                    b64e.encodeToString(e.peer.toByteArray()),
                ).joinToString("\t")
            }).joinToString("\n") + "\n"

        /** Never throws. Newest first, as stored; at most [max] entries. */
        fun decode(s: String, max: Int = MAX): List<HistoryEntry> {
            val lines = s.lineSequence().iterator()
            if (!lines.hasNext() || lines.next() != "$HEADER $VERSION") return emptyList()
            val out = ArrayList<HistoryEntry>()
            while (lines.hasNext() && out.size < max) {
                parse(lines.next())?.let { out.add(it) }
            }
            return out
        }

        private fun parse(line: String): HistoryEntry? = runCatching {
            val f = line.split('\t')
            if (f.size != 7) return null
            val at = f[0].toLong()
            val verdict = Verdict.entries.firstOrNull { it.code == f[1] } ?: return null
            val refusal = if (f[2] == "-") null else Refusal.entries.firstOrNull { it.code == f[2] } ?: return null
            // A refusal always says why, and nothing else carries a reason.
            if ((verdict == Verdict.REFUSED) != (refusal != null)) return null
            val count = f[3].toInt()
            if (at <= 0 || count < 1) return null
            val host = String(b64d.decode(f[4])).ifEmpty { null }
            if (host != null && !Hosts.validId(host)) return null
            HistoryEntry(at, verdict, refusal, host, clean(String(b64d.decode(f[5])), MAX_LABEL),
                clean(String(b64d.decode(f[6])), MAX_PEER), count)
        }.getOrNull()

        /** Control characters become spaces and the length is bounded: both come off the
         *  network (a computer chooses its own label when pairing). */
        fun clean(s: String, limit: Int): String =
            s.take(limit).map { if (it.isISOControl()) ' ' else it }.joinToString("").trim()

        /** Consecutive entries on the same local calendar day, in the order given. */
        fun groupByDay(entries: List<HistoryEntry>, zone: ZoneId): List<Pair<LocalDate, List<HistoryEntry>>> {
            val out = ArrayList<Pair<LocalDate, MutableList<HistoryEntry>>>()
            for (e in entries) {
                val day = Instant.ofEpochMilli(e.at).atZone(zone).toLocalDate()
                if (out.isEmpty() || out.last().first != day) out.add(day to mutableListOf())
                out.last().second.add(e)
            }
            return out
        }
    }

    private var list: List<HistoryEntry> = load()

    @Synchronized
    fun entries(): List<HistoryEntry> = list

    /**
     * Adds [e] at the front. A REFUSED entry identical to the newest one (same reason, computer
     * and peer; for [Refusal.OUTSIDE_LAN] any peer, since scanners change address) and within
     * [COALESCE_WINDOW_MS] of it is merged into it instead: count + 1, time and peer updated.
     * Decisions the user took part in are never merged: each is its own line.
     */
    @Synchronized
    fun record(e: HistoryEntry) {
        val entry = e.copy(label = clean(e.label, MAX_LABEL), peer = clean(e.peer, MAX_PEER))
        val top = list.firstOrNull()
        list = if (top != null && mergeable(top, entry)) {
            listOf(entry.copy(count = top.count + entry.count)) + list.drop(1)
        } else {
            (listOf(entry) + list).take(max)
        }
        save()
    }

    private fun mergeable(top: HistoryEntry, e: HistoryEntry): Boolean =
        top.verdict == Verdict.REFUSED && e.verdict == Verdict.REFUSED &&
            top.refusal == e.refusal && top.hostId == e.hostId &&
            (e.refusal == Refusal.OUTSIDE_LAN || top.peer == e.peer) &&
            e.at - top.at in 0 until COALESCE_WINDOW_MS &&
            top.count < 9_999

    @Synchronized
    fun clear() {
        list = emptyList()
        runCatching { file?.delete() }
    }

    private fun load(): List<HistoryEntry> {
        val f = file ?: return emptyList()
        return runCatching {
            if (!f.isFile || f.length() > MAX_FILE_BYTES) emptyList()
            else decode(f.readText(), max)
        }.getOrDefault(emptyList())
    }

    /** Write-then-rename, so a crash mid-write leaves the old file, never half of one. */
    private fun save() {
        val f = file ?: return
        runCatching {
            val tmp = File(f.parentFile, f.name + ".tmp")
            tmp.writeText(encode(list))
            Files.move(tmp.toPath(), f.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        }
    }
}

/** The one process-wide [History], in the app's private files directory. The service writes it
 *  and the screen reads it; both live in this process. */
object HistoryStore {
    @Volatile private var instance: History? = null

    fun get(ctx: Context): History = instance ?: synchronized(this) {
        instance ?: History(File(ctx.applicationContext.filesDir, "history-v1.txt")).also { instance = it }
    }
}
