package com.ritwick.sudostamp

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.graphics.PathMeasure
import android.view.View
import android.view.animation.DecelerateInterpolator
import android.view.animation.OvershootInterpolator

/**
 * The outcome of a request, drawn rather than written: a ring that closes, then a check (or a
 * cross) that draws itself in. Readable at a glance in the 750 ms the approval flash is up --
 * faster than a word -- and announced via contentDescription for screen readers.
 *
 * Pure platform drawing, no per-frame allocation: the paths are built once per size.
 */
class ResultMark(
    context: Context,
    private val tint: Int,
    private val approved: Boolean,
    label: String = "",
) : View(context) {

    constructor(context: Context) : this(context, Ui.ACCENT, true)

    private val density = resources.displayMetrics.density

    // The parameter is `tint`, not `color`: inside Paint().apply { } a bare `color` is the
    // Paint's own property, so `color = color` painted the whole mark default black.

    private val disc = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = (tint and 0x00FFFFFF) or 0x24000000
    }
    private val ring = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeWidth = 4f * density
        color = tint
    }
    private val mark = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
        strokeWidth = 7f * density
        color = tint
    }

    private val markPath = Path()
    private val drawn = Path()
    private val measure = PathMeasure()
    private var markLength = 0f

    private var ringT = 0f
    private var markT = 0f
    private var scale = 0.7f

    private val animator = ValueAnimator.ofFloat(0f, 1f).apply {
        duration = 520
        interpolator = DecelerateInterpolator()
        addUpdateListener {
            val t = it.animatedValue as Float
            ringT = (t / 0.55f).coerceAtMost(1f)
            markT = ((t - 0.35f) / 0.65f).coerceIn(0f, 1f)
            invalidate()
        }
    }

    private val pop = ValueAnimator.ofFloat(0.7f, 1f).apply {
        duration = 380
        interpolator = OvershootInterpolator(2.2f)
        addUpdateListener { scale = it.animatedValue as Float }
    }

    init {
        // The outcome in words for screen readers: "Expired" draws the same cross as
        // "Denied", so the caller says which.
        contentDescription = label
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        val r = minOf(w, h) / 2f
        val cx = w / 2f
        val cy = h / 2f
        markPath.reset()
        if (approved) {
            markPath.moveTo(cx - r * 0.38f, cy + r * 0.02f)
            markPath.lineTo(cx - r * 0.10f, cy + r * 0.30f)
            markPath.lineTo(cx + r * 0.40f, cy - r * 0.28f)
        } else {
            val k = r * 0.30f
            markPath.moveTo(cx - k, cy - k)
            markPath.lineTo(cx + k, cy + k)
            markPath.moveTo(cx + k, cy - k)
            markPath.lineTo(cx - k, cy + k)
        }
        // Total length across contours, so a cross draws as one continuous stroke sequence.
        markLength = 0f
        measure.setPath(markPath, false)
        do { markLength += measure.length } while (measure.nextContour())
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        animator.start()
        pop.start()
    }

    override fun onDetachedFromWindow() {
        animator.cancel()
        pop.cancel()
        super.onDetachedFromWindow()
    }

    override fun onDraw(canvas: Canvas) {
        val r = minOf(width, height) / 2f - ring.strokeWidth
        if (r <= 0) return
        val cx = width / 2f
        val cy = height / 2f
        canvas.save()
        canvas.scale(scale, scale, cx, cy)
        canvas.drawCircle(cx, cy, r, disc)
        canvas.drawArc(cx - r, cy - r, cx + r, cy + r, -90f, 360f * ringT, false, ring)

        // Draw the first markT of the mark, contour by contour.
        drawn.reset()
        var left = markLength * markT
        measure.setPath(markPath, false)
        do {
            val len = measure.length
            if (left <= 0f) break
            measure.getSegment(0f, minOf(left, len), drawn, true)
            left -= len
        } while (measure.nextContour())
        canvas.drawPath(drawn, mark)
        canvas.restore()
    }
}
