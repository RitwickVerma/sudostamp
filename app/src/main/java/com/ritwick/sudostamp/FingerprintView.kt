package com.ritwick.sudostamp

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.Shader
import android.view.View
import android.view.animation.DecelerateInterpolator
import kotlin.math.abs

/**
 * The SudoStamp mark, alive: a fingerprint with a pulsing glow behind it, a
 * rotating radar sweep, and sonar rings expanding out of it, plus a gentle
 * "breathing" pulse on the glyph itself. Pure platform drawing -- no
 * dependencies, no bitmaps -- one ValueAnimator drives everything.
 *
 * On the approval screen the sweep becomes a countdown ring ([countDown]): the arc that is
 * left is the time left before the request is denied, turning amber in the last quarter.
 */
class FingerprintView(context: Context, private val accent: Int) : View(context) {

    constructor(context: Context) : this(context, Ui.ACCENT)

    private var deadlineAt = 0L     // epoch ms; 0 = no countdown, show the radar sweep
    private var windowMs = 0L

    /** Shows a countdown ring that empties at [startedAt] + [windowMs] (epoch ms). */
    fun countDown(startedAt: Long, windowMs: Long) {
        this.deadlineAt = startedAt + windowMs
        this.windowMs = windowMs
        invalidate()
    }

    private val trackPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = Ui.OUTLINE
    }

    private val ringPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
    }

    private val sweepPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
    }

    // The glow is drawn as a unit circle scaled into place, so one gradient serves every
    // frame: radius comes from the canvas scale, the pulse from the paint's alpha. No
    // allocation per frame -- this view animates for as long as the screen is up.
    private val glowPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        shader = RadialGradient(
            0f, 0f, 1f, accent or (0xFF shl 24), Color.TRANSPARENT, Shader.TileMode.CLAMP
        )
    }

    private val sweepBounds = RectF()

    // Context.getDrawable returns a shared (constant-state) drawable; mutate()
    // so tinting this view never bleeds into another one.
    private val glyph = context.getDrawable(R.drawable.ic_logo)!!.mutate()

    private var phase = 0f

    private val animator = ValueAnimator.ofFloat(0f, 1f).apply {
        duration = 2600
        repeatCount = ValueAnimator.INFINITE
        interpolator = DecelerateInterpolator()
        addUpdateListener {
            phase = it.animatedValue as Float
            invalidate()
        }
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        animator.start()
    }

    override fun onDetachedFromWindow() {
        animator.cancel()
        super.onDetachedFromWindow()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val density = resources.displayMetrics.density

        val innerL = paddingLeft.toFloat()
        val innerT = paddingTop.toFloat()
        val w = width - paddingLeft - paddingRight
        val h = height - paddingTop - paddingBottom
        if (w <= 0 || h <= 0) return

        val cx = innerL + w / 2f
        val cy = innerT + h / 2f
        val glyphSize = minOf(w, h) * 0.5f
        val base = glyphSize / 2f
        val maxR = minOf(w, h) / 2f

        // Pulsing glow behind the glyph, so it reads as "live" rather than flat.
        val glowPulse = 1f - abs(phase - 0.5f) * 2f          // 0..1..0
        val glowAlpha = (0x28 + 0x24 * glowPulse).toInt()
        val glowRadius = base * (1.5f + 0.25f * glowPulse)
        glowPaint.alpha = glowAlpha
        canvas.save()
        canvas.translate(cx, cy)
        canvas.scale(glowRadius, glowRadius)
        canvas.drawCircle(0f, 0f, 1f, glowPaint)
        canvas.restore()

        val sweepR = maxR * 0.78f
        sweepBounds.set(cx - sweepR, cy - sweepR, cx + sweepR, cy + sweepR)
        if (windowMs > 0) {
            // Countdown: a full track, and the time that is left drawn over it clockwise
            // from twelve o'clock.
            val left = ((deadlineAt - System.currentTimeMillis()).toFloat() / windowMs).coerceIn(0f, 1f)
            trackPaint.strokeWidth = density * 4f
            canvas.drawCircle(cx, cy, sweepR, trackPaint)
            sweepPaint.strokeWidth = density * 4f
            sweepPaint.color = if (left < 0.25f) Ui.WARN else accent
            canvas.drawArc(sweepBounds, -90f, 360f * left, false, sweepPaint)
        } else {
            // Rotating radar sweep: one full turn per cycle.
            sweepPaint.strokeWidth = density * 3f
            sweepPaint.color = (accent and 0x00FFFFFF) or (0x38 shl 24)
            canvas.drawArc(sweepBounds, phase * 360f, 55f, false, sweepPaint)
        }

        // Sonar rings: three staggered pulses, expanding and fading to nothing.
        // Not around a countdown: the ring is the one moving thing that matters there.
        for (i in 0 until (if (windowMs > 0) 0 else 3)) {
            val p = (phase + i * 1f / 3f) % 1f
            val radius = base + p * (maxR - base)
            val alpha = ((1f - p) * 0x62).toInt()
            ringPaint.strokeWidth = density * (1.1f + 1.7f * (1f - p))
            ringPaint.color = (accent and 0x00FFFFFF) or (alpha shl 24)
            canvas.drawCircle(cx, cy, radius, ringPaint)
        }

        // The glyph, with a gentle breathing pulse.
        val pulse = 1f + 0.05f * (1f - abs(phase - 0.5f) * 2f)
        val s = glyphSize * pulse
        glyph.setBounds(
            (cx - s / 2f).toInt(), (cy - s / 2f).toInt(),
            (cx + s / 2f).toInt(), (cy + s / 2f).toInt()
        )
        glyph.draw(canvas)
    }
}
