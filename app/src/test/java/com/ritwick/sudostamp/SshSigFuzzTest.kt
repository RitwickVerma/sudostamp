package com.ritwick.sudostamp

import com.ritwick.sudostamp.Fuzz.readU32
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.util.Base64
import java.util.Random

/**
 * SshSig turns the Keystore's DER signature into the blob the host verifies. A mistake there is
 * silent (a plausible signature that never verifies), so the encoder is checked at the edges that
 * differ: scalars with the top bit set (a 0x00 pad), scalars with leading zero bytes (shorter
 * mpints), the smallest and largest valid values. The DER reader is also fed noise and damaged
 * signatures: it may refuse only with IllegalArgumentException, and what it accepts must be
 * exactly the canonical DER a real signer writes.
 */
class SshSigFuzzTest {

    // ------------------------------------------------------------------ reference encoders

    private val N = Der.N

    private fun der(r: BigInteger, s: BigInteger) = Der.encode(r, s)

    private class Parsed(val type: String, val r: ByteArray, val s: ByteArray, val inner: Int)

    /** The SSH strings in [b], insisting every byte is accounted for. */
    private fun strings(b: ByteArray): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        var o = 0
        while (o < b.size) {
            assertTrue("a length field at $o of ${b.size}", o + 4 <= b.size)
            val n = readU32(b, o)
            assertTrue("string of $n at $o of ${b.size}", n >= 0 && n <= b.size - o - 4)
            out += b.copyOfRange(o + 4, o + 4 + n)
            o += 4 + n
        }
        return out
    }

    /** Reads a signature blob back with no shared code. */
    private fun parse(blob: ByteArray): Parsed {
        val top = strings(blob)
        assertEquals("type and inner, nothing else", 2, top.size)
        val rs = strings(top[1])
        assertEquals("r and s, nothing else", 2, rs.size)
        return Parsed(String(top[0], Charsets.US_ASCII), rs[0], rs[1], top[1].size)
    }

    /** RFC 4251 mpint of a positive number: minimal, and a 0x00 only where the top bit needs one. */
    private fun assertMpint(name: String, b: ByteArray, v: BigInteger) {
        assertTrue("$name non-empty", b.isNotEmpty())
        assertTrue("$name is positive (top bit clear)", b[0].toInt() and 0x80 == 0)
        if (b.size > 1 && b[0] == 0.toByte()) assertTrue("$name: a 0x00 pad only before a set top bit", b[1].toInt() and 0x80 != 0)
        assertEquals("$name value", v, BigInteger(1, b))
    }

    private fun checkRoundTrip(r: BigInteger, s: BigInteger) {
        val blob = SshSig.signatureBlob(der(r, s))
        val p = parse(blob)
        assertEquals(SshSig.KEY_TYPE, p.type)
        assertMpint("r", p.r, r)
        assertMpint("s", p.s, s)
        assertEquals("blob size is the two strings plus the framing", 4 + 19 + 4 + 8 + p.r.size + p.s.size, blob.size)
        assertEquals(8 + p.r.size + p.s.size, p.inner)
        // A set top bit costs one pad byte; and a full-width pair stays inside the SSH range:
        // inner 72..74 bytes, whole blob 99..101.
        for ((v, m) in listOf(r to p.r, s to p.s)) {
            assertEquals("a pad byte exactly when the top bit of the last byte would be set", v.bitLength() % 8 == 0, m.size > 1 && m[0] == 0.toByte())
        }
        if (r.bitLength() in 249..256 && s.bitLength() in 249..256) {
            assertTrue("inner ${p.inner}", p.inner in 72..74)
            assertTrue("blob ${blob.size}", blob.size in 99..101)
        }
        assertTrue("a P-256 signature stays under the 74 byte inner bound: ${p.inner}", p.inner <= 74)
    }

    // ------------------------------------------------------------------ encoder

    @Test
    fun `boundary scalars encode, parse back and keep their sizes`() {
        val edges = linkedSetOf(
            BigInteger.ONE, BigInteger.TWO, BigInteger.valueOf(0x7F), BigInteger.valueOf(0x80), BigInteger.valueOf(0xFF),
            BigInteger.valueOf(0x100), BigInteger.valueOf(0x8000), BigInteger.valueOf(0x7FFF),
            BigInteger.ONE.shiftLeft(247), BigInteger.ONE.shiftLeft(248), BigInteger.ONE.shiftLeft(248).subtract(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE), BigInteger.ONE.shiftLeft(255), BigInteger.ONE.shiftLeft(255).add(BigInteger.ONE),
            N.subtract(BigInteger.ONE), N.subtract(BigInteger.TWO), N.shiftRight(1), N.shiftRight(1).add(BigInteger.ONE),
        )
        for (k in 1..255 step 7) edges += BigInteger.ONE.shiftLeft(k)
        for (r in edges) for (s in edges) checkRoundTrip(r, s)
    }

    @Test
    fun `random scalars incl top bit set and leading zero bytes encode and parse back`() {
        Fuzz.run("sig/roundtrip", 11) { _, rnd ->
            fun scalar(): BigInteger {
                // 1..n-1, then a random number of whole leading bytes shaved off: leading zeros.
                var v = BigInteger(256, rnd).mod(N.subtract(BigInteger.ONE)).add(BigInteger.ONE)
                if (rnd.nextInt(3) == 0) v = v.shiftRight(8 * rnd.nextInt(32))
                if (v.signum() == 0) v = BigInteger.ONE
                if (rnd.nextInt(5) == 0) v = v.setBit(255).mod(N).max(BigInteger.ONE)
                return v
            }
            checkRoundTrip(scalar(), scalar())
        }
    }

    @Test
    fun `real Keystore-shaped signatures encode to a blob a second parser reads`() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        Fuzz.run("sig/real", 12, weight = 2) { i, rnd ->
            val sig = Signature.getInstance("SHA256withECDSA").apply { initSign(kp.private); update(Fuzz.bytes(rnd, 1 + rnd.nextInt(40)) + i.toByte()) }.sign()
            val (r, s) = SshSig.derToRs(sig)
            assertArrayEquals("DER re-encodes identically", sig, der(r, s))
            checkRoundTrip(r, s)
        }
    }

    // ------------------------------------------------------------------ DER reader

    /** What derToRs may do with any input: return a positive pair, or throw IllegalArgumentException. */
    private fun assertOnlyDocumented(input: ByteArray) {
        val (r, s) = try {
            SshSig.derToRs(input)
        } catch (e: IllegalArgumentException) {
            return
        }
        assertTrue("positive", r.signum() > 0 && s.signum() > 0)
    }

    @Test
    fun `the DER reader throws only IllegalArgumentException on noise and damaged signatures`() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val valid = (0 until 16).map { i ->
            Signature.getInstance("SHA256withECDSA").apply { initSign(kp.private); update(byteArrayOf(i.toByte())) }.sign()
        }
        Fuzz.run("der/damaged", 13) { _, rnd ->
            assertOnlyDocumented(Der.damaged(rnd, valid[rnd.nextInt(valid.size)]))
        }
    }

    // ------------------------------------------------------------------ key blob

    private val params: ECParameterSpec = (KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair().public as ECPublicKey).params

    private class FakeKey(private val point: ECPoint, private val spec: ECParameterSpec) : ECPublicKey {
        override fun getW() = point
        override fun getParams() = spec
        override fun getAlgorithm() = "EC"
        override fun getFormat() = "X.509"
        override fun getEncoded() = ByteArray(0)
    }

    private fun padded(v: BigInteger): ByteArray = ByteArray(32).also { out ->
        val b = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        System.arraycopy(b, 0, out, 32 - b.size, b.size)
    }

    @Test
    fun `key blob and authorized_keys line for any coordinates are fixed width and decode back`() {
        val edges = listOf(BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(0x80), BigInteger.ONE.shiftLeft(248),
            BigInteger.ONE.shiftLeft(255), BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE))
        fun check(x: BigInteger, y: BigInteger, comment: String?) {
            val key = FakeKey(ECPoint(x, y), params)
            val blob = SshSig.keyBlob(key)
            assertEquals(4 + 19 + 4 + 8 + 4 + 65, blob.size)
            assertEquals(19, readU32(blob, 0)); assertEquals(8, readU32(blob, 23)); assertEquals(65, readU32(blob, 35))
            assertEquals(0x04, blob[39].toInt())
            assertArrayEquals("x", padded(x), blob.copyOfRange(40, 72))
            assertArrayEquals("y", padded(y), blob.copyOfRange(72, 104))
            val line = SshSig.authorizedKeyLine(key, comment)
            val fields = line.split(" ")
            assertEquals(SshSig.KEY_TYPE, fields[0])
            assertArrayEquals(blob, Base64.getDecoder().decode(fields[1]))
            if (comment.isNullOrEmpty()) assertEquals(2, fields.size) else assertEquals("$comment", line.substringAfter(fields[1] + " "))
        }
        for (x in edges) for (y in edges) check(x, y, "sudostamp")
        Fuzz.run("keyblob/random", 15, weight = 50) { _, rnd ->
            val x = BigInteger(1 + rnd.nextInt(256), rnd)
            val y = BigInteger(1 + rnd.nextInt(256), rnd)
            check(x, y, listOf(null, "", "a", "name with spaces", "x".repeat(40))[rnd.nextInt(5)])
        }
    }
}
