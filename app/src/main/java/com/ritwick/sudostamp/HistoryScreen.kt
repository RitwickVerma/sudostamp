package com.ritwick.sudostamp

import android.content.Context
import android.text.format.DateFormat
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import com.ritwick.sudostamp.Ui.Kind
import com.ritwick.sudostamp.Ui.Type
import com.ritwick.sudostamp.Ui.button
import com.ritwick.sudostamp.Ui.card
import com.ritwick.sudostamp.Ui.column
import com.ritwick.sudostamp.Ui.divider
import com.ritwick.sudostamp.Ui.dp
import com.ritwick.sudostamp.Ui.dpf
import com.ritwick.sudostamp.Ui.matchWrap
import com.ritwick.sudostamp.Ui.row
import com.ritwick.sudostamp.Ui.tag
import com.ritwick.sudostamp.Ui.text
import com.ritwick.sudostamp.Ui.wrap
import java.time.LocalDate
import java.time.ZoneId

/**
 * The History screen's content, built from the pure [History]. A refused request is drawn
 * apart (a red-tinted box, a shield, and one sentence on what it means): those were decided
 * without ever reaching the screen, so this list is the only place the user can see them.
 */
object HistoryScreen {

    private data class Look(val label: Int, val detail: Int, val color: Int, val dim: Int, val icon: Int)

    private const val MUTED_DIM = 0x268A97AD

    private fun look(e: HistoryEntry): Look = when (e.verdict) {
        Verdict.APPROVED -> Look(R.string.verdict_approved, R.string.verdict_approved_detail,
            Ui.ACCENT, Ui.ACCENT_DIM, R.drawable.ic_check_circle)
        Verdict.DENIED -> Look(R.string.verdict_denied, R.string.verdict_denied_detail,
            Ui.MUTED, MUTED_DIM, R.drawable.ic_do_not_disturb_on)
        Verdict.DENIED_NOTIFICATION -> Look(R.string.verdict_denied_notification, R.string.verdict_denied_notification_detail,
            Ui.MUTED, MUTED_DIM, R.drawable.ic_do_not_disturb_on)
        Verdict.TIMED_OUT -> Look(R.string.verdict_timed_out, R.string.verdict_timed_out_detail,
            Ui.WARN, Ui.WARN_DIM, R.drawable.ic_schedule)
        Verdict.CANCELLED -> Look(R.string.verdict_cancelled, R.string.verdict_cancelled_detail,
            Ui.MUTED, MUTED_DIM, R.drawable.ic_pause)
        Verdict.REFUSED -> Look(R.string.verdict_refused, refusalText(e.refusal),
            Ui.DANGER, Ui.DANGER_DIM, R.drawable.ic_shield)
    }

    private fun refusalText(r: Refusal?): Int = when (r) {
        Refusal.UNKNOWN_KEY, null -> R.string.refusal_unknown_key
        Refusal.NOT_A_CHALLENGE -> R.string.refusal_not_a_challenge
        Refusal.OUTSIDE_LAN -> R.string.refusal_outside_lan
        Refusal.RATE_LIMITED -> R.string.refusal_rate_limited
        Refusal.AFTER_APPROVAL -> R.string.refusal_after_approval
        Refusal.COOLDOWN -> R.string.refusal_cooldown
    }

    /** Who the entry names: the computer, or "unknown device" for a peer that is not paired. */
    fun name(ctx: Context, e: HistoryEntry): String = when {
        e.hostId == null -> ctx.getString(R.string.history_unknown_device)
        else -> Ui.hostName(ctx, e.hostId, e.label)
    }

    private fun dayLabel(ctx: Context, day: LocalDate, today: LocalDate): String = when (day) {
        today -> ctx.getString(R.string.history_today)
        today.minusDays(1) -> ctx.getString(R.string.history_yesterday)
        else -> DateFormat.getMediumDateFormat(ctx).format(
            java.util.Date.from(day.atStartOfDay(ZoneId.systemDefault()).toInstant())
        )
    }

    /** Fills a screen column: back, title, what this is, the days, and Clear. */
    fun LinearLayout.build(entries: List<HistoryEntry>, onBack: () -> Unit, onClear: () -> Unit) {
        val ctx = context
        val zone = ZoneId.systemDefault()
        val today = LocalDate.now(zone)
        // With seconds: "within 3 seconds of an approval" is only checkable if the list shows them.
        val time = java.text.DateFormat.getTimeInstance(java.text.DateFormat.MEDIUM)

        addView(ctx.button(ctx.getString(R.string.history_back), Kind.GHOST) { onBack() },
            wrap(bottom = ctx.dp(4)).apply {
                gravity = Gravity.START
                leftMargin = -ctx.dp(20)    // the ghost button's own padding: text lines up with the title
            })
        addView(ctx.text(ctx.getString(R.string.history_title), Type.DISPLAY), matchWrap())
        addView(ctx.text(ctx.getString(R.string.history_intro), Type.CAPTION, Ui.MUTED), matchWrap(top = ctx.dp(8), bottom = ctx.dp(20)))

        if (entries.isEmpty()) {
            addView(ctx.card().apply {
                addView(ctx.text(ctx.getString(R.string.history_empty), Type.BODY, Ui.MUTED))
            }, matchWrap())
            return
        }

        for ((day, list) in History.groupByDay(entries, zone)) {
            addView(ctx.text(dayLabel(ctx, day, today), Type.OVERLINE, Ui.FAINT), matchWrap(top = ctx.dp(12), bottom = ctx.dp(8)))
            addView(ctx.card().apply {
                list.forEachIndexed { i, e ->
                    if (i > 0) addView(ctx.divider())
                    addView(entryView(ctx, e, time), matchWrap().apply {
                        // A refused entry's box reaches into the card padding, so its text lines up.
                        if (e.verdict == Verdict.REFUSED) { leftMargin = -ctx.dp(12); rightMargin = -ctx.dp(12) }
                    })
                }
            }, matchWrap())
        }
        addView(ctx.button(ctx.getString(R.string.history_clear), Kind.DANGER) { onClear() }, matchWrap(top = ctx.dp(28)))
    }

    private fun entryView(ctx: Context, e: HistoryEntry, time: java.text.DateFormat): View {
        val l = look(e)
        val name = name(ctx, e)
        val at = time.format(e.at)
        val verdict = ctx.getString(l.label)
        val detail = ctx.getString(l.detail)
        val refused = e.verdict == Verdict.REFUSED
        val repeats = if (e.count > 1) ctx.resources.getQuantityString(R.plurals.history_times, e.count, e.count, at) else null

        val box = ctx.column(Gravity.START).apply {
            if (refused) {
                background = Ui.rounded(Ui.DANGER_DIM, ctx.dpf(12f))
                setPadding(ctx.dp(12), ctx.dp(10), ctx.dp(12), ctx.dp(12))
            }
            addView(ctx.row().apply {
                addView(ctx.tag(verdict, l.color, l.dim, l.icon))
                addView(View(ctx), LinearLayout.LayoutParams(0, 1, 1f))
                addView(ctx.text(at, Type.CAPTION, Ui.MUTED))
            }, matchWrap())
            addView(ctx.text(name, Type.LABEL), matchWrap(top = ctx.dp(8)))
            addView(ctx.text(ctx.getString(R.string.history_peer, e.peer.ifEmpty { "?" }), Type.CODE_SMALL, Ui.MUTED), matchWrap(top = ctx.dp(2)))
            if (repeats != null) addView(ctx.text(repeats, Type.CAPTION, Ui.DANGER), matchWrap(top = ctx.dp(2)))
            addView(ctx.text(detail, Type.CAPTION, if (refused) Ui.FG else Ui.MUTED), matchWrap(top = ctx.dp(6)))
        }
        // One stop for a screen reader, in reading order, instead of six.
        box.contentDescription = listOfNotNull(
            "$verdict, $name, ${e.peer}, $at", repeats, detail
        ).joinToString(". ")
        box.isScreenReaderFocusable = true
        hideChildren(box)
        return box
    }

    private fun hideChildren(v: ViewGroup) {
        for (i in 0 until v.childCount) {
            val c = v.getChildAt(i)
            c.importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            if (c is ViewGroup) hideChildren(c)
        }
    }
}
