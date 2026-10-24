package com.ritwick.sudostamp

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.text.TextUtils
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView

/**
 * The app's whole design system: colours, type, and the handful of components the screens are
 * built from. Plain platform views on purpose -- no AndroidX, no Material Components -- because
 * zero runtime dependencies is a security property of this app, not a style choice.
 *
 * One dark scheme, always: the app is opened for a few seconds at a time, often straight off a
 * notification at night, and a near-black ground with one green accent reads instantly.
 */
object Ui {

    // Ground and surfaces, darkest to lightest.
    const val BG = 0xFF0B0D12.toInt()
    const val SURFACE = 0xFF141821.toInt()
    const val SURFACE_HI = 0xFF1C2230.toInt()
    const val OUTLINE = 0xFF252C3B.toInt()

    // Text.
    const val FG = 0xFFE7EDF7.toInt()
    const val MUTED = 0xFF8A97AD.toInt()
    const val FAINT = 0xFF5B6577.toInt()

    // Meaning. Each has a dim tint for backgrounds behind it.
    const val ACCENT = 0xFF4ADE80.toInt()
    const val ACCENT_DIM = 0x264ADE80
    const val WARN = 0xFFFBBF24.toInt()
    const val WARN_DIM = 0x26FBBF24
    const val DANGER = 0xFFF87171.toInt()
    const val DANGER_DIM = 0x26F87171
    const val ON_ACCENT = 0xFF06210F.toInt()

    private val SANS = Typeface.create("sans-serif", Typeface.NORMAL)
    private val SANS_MEDIUM = Typeface.create("sans-serif-medium", Typeface.NORMAL)

    /** How a paired computer is named on screen: its own label, or, for the one shared key of
     *  versions before 1.4, what that key stands for. */
    fun hostName(ctx: Context, hostId: String, label: String): String =
        if (hostId == Hosts.LEGACY_ID) ctx.getString(R.string.host_legacy) else label

    fun Context.dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()
    fun Context.dpf(v: Float): Float = v * resources.displayMetrics.density

    fun rounded(color: Int, radius: Float, stroke: Int = 0, strokeColor: Int = 0) =
        GradientDrawable().apply {
            setColor(color)
            cornerRadius = radius
            if (stroke > 0) setStroke(stroke, strokeColor)
        }

    // ------------------------------------------------------------------ type

    enum class Type(val sp: Float, val medium: Boolean, val mono: Boolean = false, val tracking: Float = 0f) {
        DISPLAY(30f, true, tracking = -0.01f),
        TITLE(20f, true),
        BODY(15f, false),
        LABEL(15f, true),
        CAPTION(13f, false),
        OVERLINE(11f, true, tracking = 0.12f),
        CODE(14f, false, mono = true),
        CODE_SMALL(12.5f, false, mono = true),
    }

    fun Context.text(s: CharSequence, type: Type, color: Int = FG, center: Boolean = false): TextView =
        TextView(this).apply {
            text = s
            setTextSize(TypedValue.COMPLEX_UNIT_SP, type.sp)
            setTextColor(color)
            typeface = when {
                type.mono -> Typeface.MONOSPACE
                type.medium -> SANS_MEDIUM
                else -> SANS
            }
            letterSpacing = type.tracking
            if (type == Type.OVERLINE) isAllCaps = true
            setLineSpacing(0f, if (type.mono) 1.15f else 1.25f)
            if (center) gravity = Gravity.CENTER_HORIZONTAL
        }

    // ------------------------------------------------------------------ layout

    fun Context.column(gravity: Int = Gravity.CENTER_HORIZONTAL): LinearLayout =
        LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            this.gravity = gravity
        }

    fun Context.row(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
    }

    fun matchWrap(top: Int = 0, bottom: Int = 0) = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
    ).apply { topMargin = top; bottomMargin = bottom }

    fun wrap(top: Int = 0, bottom: Int = 0) = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT
    ).apply { topMargin = top; bottomMargin = bottom; gravity = Gravity.CENTER_HORIZONTAL }

    /** A card: rounded surface with a hairline outline, holding a vertical stack. */
    fun Context.card(): LinearLayout = column(Gravity.START).apply {
        background = rounded(SURFACE, dpf(20f), dp(1), OUTLINE)
        setPadding(dp(20), dp(18), dp(20), dp(18))
    }

    /** A thin divider between rows inside a card. */
    fun Context.divider(): View = View(this).apply {
        setBackgroundColor(OUTLINE)
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1))
            .apply { topMargin = dp(14); bottomMargin = dp(14) }
    }

    fun Context.icon(res: Int, tint: Int, sizeDp: Int = 22): ImageView = ImageView(this).apply {
        setImageResource(res)
        imageTintList = ColorStateList.valueOf(tint)
        layoutParams = LinearLayout.LayoutParams(dp(sizeDp), dp(sizeDp))
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
    }

    // ------------------------------------------------------------------ components

    /** A status pill: a dot or icon and a short state, on a tint of its colour. Announced
     *  politely when it changes, so a state change is not visual-only. */
    fun Context.pill(label: String, color: Int, dim: Int, iconRes: Int): LinearLayout = row().apply {
        background = rounded(dim, dpf(100f))
        setPadding(dp(12), dp(7), dp(16), dp(7))
        addView(icon(iconRes, color, 18))
        addView(text(label, Type.LABEL, color).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            setPadding(dp(8), 0, 0, 0)
        })
        accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        contentDescription = label
    }

    enum class Kind { PRIMARY, SECONDARY, DANGER, GHOST }

    /** A real Button (so it is announced as one), restyled: rounded, ripple, 52dp tall. */
    fun Context.button(label: String, kind: Kind, iconRes: Int? = null, onClick: () -> Unit): Button =
        Button(this).apply {
            text = label
            isAllCaps = false
            stateListAnimator = null
            typeface = SANS_MEDIUM
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
            minHeight = dp(52)
            minimumHeight = dp(52)
            setPadding(dp(20), 0, dp(20), 0)
            val (bg, fg, stroke) = when (kind) {
                Kind.PRIMARY -> Triple(ACCENT, ON_ACCENT, 0)
                Kind.SECONDARY -> Triple(SURFACE_HI, FG, OUTLINE)
                Kind.DANGER -> Triple(DANGER_DIM, DANGER, 0)
                Kind.GHOST -> Triple(0, MUTED, 0)
            }
            setTextColor(fg)
            val shape = rounded(bg, dpf(16f), if (stroke != 0) dp(1) else 0, stroke)
            background = RippleDrawable(
                ColorStateList.valueOf((fg and 0x00FFFFFF) or 0x33000000),
                shape,
                rounded(-0x1, dpf(16f))
            )
            if (iconRes != null) {
                // The icon travels inline with the label so the pair is centred together;
                // a compound drawable would pin it to the button's edge instead.
                val d = getDrawable(iconRes)!!.mutate().apply {
                    setTint(fg)
                    setBounds(0, 0, dp(20), dp(20))
                }
                text = android.text.SpannableString("\u200B  $label").apply {
                    setSpan(
                        android.text.style.ImageSpan(d, android.text.style.DynamicDrawableSpan.ALIGN_CENTER),
                        0, 1, android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                    )
                }
                contentDescription = label
            }
            setOnClickListener { onClick() }
        }

    /**
     * One line of a checklist: icon, title, detail, and an optional action on the right.
     * A row that is fine shows a green check and no action -- "done" must look done.
     */
    fun Context.checkRow(
        iconRes: Int,
        ok: Boolean,
        title: String,
        detail: String,
        action: Pair<String, () -> Unit>? = null,
    ): LinearLayout = row().apply {
        gravity = Gravity.CENTER_VERTICAL
        val tint = if (ok) ACCENT else WARN
        addView(FrameBadge(this@checkRow, iconRes, tint, if (ok) ACCENT_DIM else WARN_DIM))
        addView(column(Gravity.START).apply {
            setPadding(dp(14), 0, dp(8), 0)
            addView(text(title, Type.LABEL))
            addView(text(detail, Type.CAPTION, MUTED).apply {
                maxLines = 3
                ellipsize = TextUtils.TruncateAt.END
            })
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        if (action != null) {
            addView(text(action.first, Type.LABEL, ACCENT).apply {
                setPadding(dp(12), dp(12), dp(4), dp(12))
                minWidth = dp(48)
                background = RippleDrawable(
                    ColorStateList.valueOf(ACCENT_DIM), null, rounded(-0x1, dpf(12f))
                )
                isClickable = true
                isFocusable = true
                setOnClickListener { action.second() }
            })
        }
    }

    /** A labelled value inside a card: small overline, then the value (mono if code). */
    fun Context.field(label: String, value: String, mono: Boolean): LinearLayout =
        column(Gravity.START).apply {
            addView(text(label, Type.OVERLINE, FAINT))
            addView(text(value, if (mono) Type.CODE else Type.BODY).apply {
                setPadding(0, dp(6), 0, 0)
                // Values can be selected and copied piecemeal; labels and counters cannot,
                // so a long-press on the countdown does not start a text selection.
                setTextIsSelectable(true)
                breakStrategy = android.graphics.text.LineBreaker.BREAK_STRATEGY_SIMPLE
            })
        }

    /** An icon centred on a soft tinted circle. */
    class FrameBadge(ctx: Context, iconRes: Int, tint: Int, dim: Int) : android.widget.FrameLayout(ctx) {
        constructor(ctx: Context) : this(ctx, R.drawable.ic_check_circle, ACCENT, ACCENT_DIM)

        init {
            val size = ctx.dp(40)
            layoutParams = LinearLayout.LayoutParams(size, size)
            background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(dim)
            }
            addView(ctx.icon(iconRes, tint, 22).apply {
                layoutParams = LayoutParams(ctx.dp(22), ctx.dp(22), Gravity.CENTER)
            })
        }
    }

    /**
     * A vertical stack that never grows wider than [maxWidthDp] and centres itself. On a phone
     * it is simply the screen width; on a foldable's inner screen or in landscape it keeps line
     * lengths readable instead of stretching buttons across a tablet.
     */
    class Column @JvmOverloads constructor(ctx: Context, private val maxWidthDp: Int = 460) : LinearLayout(ctx) {
        init {
            orientation = VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
        }

        override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
            val max = context.dp(maxWidthDp)
            val w = MeasureSpec.getSize(widthMeasureSpec)
            val spec = if (w > max) MeasureSpec.makeMeasureSpec(max, MeasureSpec.EXACTLY) else widthMeasureSpec
            super.onMeasure(spec, heightMeasureSpec)
        }
    }
}
