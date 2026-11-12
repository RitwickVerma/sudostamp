package com.ritwick.sudostamp

import java.math.BigInteger
import java.util.Random

/**
 * Shared plumbing for the fuzz and property tests (`*FuzzTest`).
 *
 * WHY HAND-ROLLED: the project has no test dependency but JUnit, and that is a security property
 * of the build (docs/DESIGN.md). Every generator here is a java.util.Random with a fixed seed, so
 * a failure is the same failure on every machine and every CI run: the message names the seed and
 * iteration, and `-Dsudostamp.fuzz.seed=<n>` replays it.
 *
 * Size: [iterations] cases per property, 20 000 by default, which keeps the whole suite to a few
 * seconds on the CI runner. A long local run:
 *
 *     SUDOSTAMP_FUZZ_ITERATIONS=2000000 ./gradlew testDebugUnitTest --tests '*FuzzTest' --rerun-tasks
 *
 * or `-Dsudostamp.fuzz.iterations=2000000` (forwarded to the test JVM by app/build.gradle.kts).
 */
object Fuzz {
    private const val DEFAULT_ITERATIONS = 20_000L
    private const val DEFAULT_SEED = 0x5D0570A4D5L

    private fun setting(property: String, env: String): String? =
        System.getProperty(property)?.takeIf { it.isNotBlank() } ?: System.getenv(env)?.takeIf { it.isNotBlank() }

    val iterations: Long = setting("sudostamp.fuzz.iterations", "SUDOSTAMP_FUZZ_ITERATIONS")
        ?.toLongOrNull()?.coerceAtLeast(1) ?: DEFAULT_ITERATIONS

    val seed: Long = setting("sudostamp.fuzz.seed", "SUDOSTAMP_FUZZ_SEED")?.toLongOrNull() ?: DEFAULT_SEED

    /** What ran, so a long run can be reported: property name to cases. */
    val counts: MutableMap<String, Long> = java.util.Collections.synchronizedMap(LinkedHashMap())

    /**
     * Runs [body] for [iterations] * [weight] / 100 cases (at least 1) with a Random seeded from
     * [seed] and [salt], so two properties never share a stream. A failure is rethrown with what
     * is needed to replay it.
     */
    fun run(name: String, salt: Long, weight: Int = 100, body: (Int, Random) -> Unit) {
        val rnd = Random(seed * -7046029254386353131L + salt)
        val n = (iterations * weight / 100).coerceAtLeast(1)
        var i = 0L
        try {
            while (i < n) {
                body(i.toInt(), rnd)
                i++
            }
        } catch (t: Throwable) {
            throw AssertionError("$name: seed=$seed iteration=$i of $n (replay: -Dsudostamp.fuzz.seed=$seed): $t", t)
        }
        counts[name] = n
        println("fuzz $name: $n cases, seed $seed")
    }

    // ---- byte helpers shared by the tests

    fun bytes(r: Random, n: Int): ByteArray = ByteArray(n).also { r.nextBytes(it) }

    fun u32(v: Int): ByteArray = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    fun readU32(b: ByteArray, at: Int): Int =
        ((b[at].toInt() and 0xFF) shl 24) or ((b[at + 1].toInt() and 0xFF) shl 16) or
            ((b[at + 2].toInt() and 0xFF) shl 8) or (b[at + 3].toInt() and 0xFF)

    /** An SSH string: uint32 length, then the bytes. */
    fun str(b: ByteArray): ByteArray = u32(b.size) + b

    fun str(s: String): ByteArray = str(s.toByteArray(Charsets.US_ASCII))

    /** Lengths a hostile peer writes: zero, negative, at the cap, one over, the int limits. */
    val LIES = intArrayOf(
        0, 1, 2, 3, 4, 5, 31, 32, 33, 64 * 1024 - 1, 64 * 1024, 64 * 1024 + 1, 0xFFFF, 0x10000,
        -1, -2, Int.MIN_VALUE, Int.MIN_VALUE + 1, Int.MAX_VALUE, Int.MAX_VALUE - 1, Int.MAX_VALUE - 4,
        0x7FFF0000, 0x80000000.toInt(),
    )
}

/** DER SEQUENCE { INTEGER r, INTEGER s } as a signer writes it, and ways to damage it. */
object Der {
    /** The order n of the P-256 group: a valid ECDSA r or s lies in 1..n-1. */
    val N = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

    fun len(n: Int): ByteArray = when {
        n < 0x80 -> byteArrayOf(n.toByte())
        n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
        else -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
    }

    fun int(v: BigInteger): ByteArray = v.toByteArray().let { byteArrayOf(0x02) + len(it.size) + it }

    /** A SEQUENCE around [content], with the correct minimal length. */
    fun seq(content: ByteArray): ByteArray = byteArrayOf(0x30) + len(content.size) + content

    fun encode(r: BigInteger, s: BigInteger): ByteArray = seq(int(r) + int(s))

    fun damaged(rnd: Random, valid: ByteArray): ByteArray = when (rnd.nextInt(7)) {
        0 -> valid.copyOf(rnd.nextInt(valid.size + 1))
        1 -> valid.copyOf().also { repeat(1 + rnd.nextInt(3)) { _ -> it[rnd.nextInt(it.size)] = rnd.nextInt(256).toByte() } }
        2 -> valid + Fuzz.bytes(rnd, 1 + rnd.nextInt(8))
        3 -> valid.copyOf().also { it[rnd.nextInt(minOf(it.size, 6))] = Fuzz.LIES[rnd.nextInt(Fuzz.LIES.size)].toByte() }
        4 -> Fuzz.bytes(rnd, rnd.nextInt(90))
        5 -> byteArrayOf(0x30) + Fuzz.bytes(rnd, rnd.nextInt(80))
        else -> valid.copyOf().also { it[0] = rnd.nextInt(256).toByte() }
    }
}
