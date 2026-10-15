package com.ritwick.sudostamp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * Verifies the SSH encoding, on the JVM, with no Android involved.
 *
 * WHY THIS TEST EXISTS: SshSig turns a Keystore DER signature into the SSH agent's
 * nested blob. If that encoding is wrong, nothing crashes -- the app signs, the server
 * rejects, and it only shows up on real hardware when you actually need it. The Kotlin
 * port was itself a rewrite of already-verified Java, so it has to be re-proven.
 *
 * Two layers of checking:
 *   1. HERE: structural properties and negative controls (deterministic, runs in CI).
 *   2. EXTERNALLY: this test writes test.pub / msg.bin / sig.bin into build/sshcheck/,
 *      and tools/verify_ssh_sig.py then confirms them with real `ssh-keygen` and an
 *      independent ECDSA implementation. Structure tests can pass on a blob that no
 *      real verifier accepts; only the external check rules that out.
 */
class SshSigTest {

    private fun newKey(): ECPublicKey {
        val g = KeyPairGenerator.getInstance("EC")
        g.initialize(ECGenParameterSpec("secp256r1"))
        return g.generateKeyPair().public as ECPublicKey
    }

    @Test
    fun `key blob has the exact ssh structure`() {
        val blob = SshSig.keyBlob(newKey())
        // string "ecdsa-sha2-nistp256" | string "nistp256" | string (65-byte point)
        val expected = 4 + 19 + 4 + 8 + 4 + 65
        assertEquals("blob length", expected, blob.size)
        assertEquals("first string length", 19, readU32(blob, 0))
        assertEquals("ecdsa-sha2-nistp256", String(blob, 4, 19, Charsets.US_ASCII))
        assertEquals("curve length", 8, readU32(blob, 23))
        assertEquals("nistp256", String(blob, 27, 8, Charsets.US_ASCII))
        assertEquals("point length", 65, readU32(blob, 35))
        assertEquals("uncompressed marker", 0x04, blob[39].toInt())
    }

    @Test
    fun `authorized key line is parseable and stable`() {
        val pub = newKey()
        val line = SshSig.authorizedKeyLine(pub, "sudostamp")
        assertTrue("starts with key type", line.startsWith("ecdsa-sha2-nistp256 "))
        assertTrue("ends with comment", line.endsWith(" sudostamp"))
        val b64 = line.split(" ")[1]
        assertArrayEquals("base64 round-trips", SshSig.keyBlob(pub), Base64.getDecoder().decode(b64))
        // Two calls must give the same string, or the user could paste a stale key.
        assertEquals(line, SshSig.authorizedKeyLine(pub, "sudostamp"))
    }

    @Test
    fun `signature blob wraps r and s correctly`() {
        val kp = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val msg = "hello".toByteArray()
        val der = Signature.getInstance("SHA256withECDSA").run {
            initSign(kp.private); update(msg); sign()
        }
        val blob = SshSig.signatureBlob(der)

        assertEquals("sig type length", 19, readU32(blob, 0))
        assertEquals("ecdsa-sha2-nistp256", String(blob, 4, 19, Charsets.US_ASCII))
        val innerLen = readU32(blob, 23)
        assertEquals("inner container length", blob.size - 27, innerLen)

        // inner = string r, string s
        val rLen = readU32(blob, 27)
        val r = blob.copyOfRange(31, 31 + rLen)
        val sLen = readU32(blob, 31 + rLen)
        val s = blob.copyOfRange(35 + rLen, 35 + rLen + sLen)
        assertEquals("inner fully consumed", 27 + innerLen, 35 + rLen + sLen)

        // mpint rules: a leading 0x00 is allowed ONLY when the next byte has its high bit set.
        for ((name, b) in listOf("r" to r, "s" to s)) {
            assertTrue("$name non-empty", b.isNotEmpty())
            if (b.size > 1 && b[0] == 0.toByte()) {
                assertTrue("$name leading zero must be required", b[1].toInt() and 0x80 != 0)
            }
        }

        // The mpints must encode EXACTLY the values the DER carried. Without this the
        // test would pass on any well-shaped pair of numbers -- which is precisely the
        // bug that would break verification on the server.
        val (derR, derS) = SshSig.derToRs(der)
        assertEquals("r matches DER", derR, BigInteger(1, r))
        assertEquals("s matches DER", derS, BigInteger(1, s))
    }

    @Test
    fun `derToRs recovers the original r and s`() {
        val r = BigInteger("12345678901234567890123456789012345678901234567890")
        val s = BigInteger("98765432109876543210987654321098765432109876543210")
        val der = derEncode(r, s)
        val (gotR, gotS) = SshSig.derToRs(der)
        assertEquals("r", r, gotR)
        assertEquals("s", s, gotS)
    }

    @Test
    fun `derToRs rejects malformed input instead of guessing`() {
        val bad = listOf(
            "empty" to ByteArray(0),
            "truncated" to byteArrayOf(0x30, 0x06, 0x02, 0x01),
            "not-a-sequence" to byteArrayOf(0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01),
            "zero-r" to byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01),
            "zero-s" to byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00),
            "trailing-bytes" to byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00),
            "seq-len-too-short" to byteArrayOf(0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01),
            "seq-len-too-long" to byteArrayOf(0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01),
            "truncated-long-length" to byteArrayOf(0x30, 0x82.toByte(), 0x00),
            "integer-too-wide" to derEncode(BigInteger.ONE.shiftLeft(270), BigInteger.ONE),
            "zero-length-integer" to byteArrayOf(0x30, 0x06, 0x02, 0x00, 0x02, 0x02, 0x01, 0x01)
        )
        for ((name, der) in bad) {
            val threw = try {
                SshSig.signatureBlob(der); false
            } catch (e: RuntimeException) {
                true
            }
            assertTrue("must reject $name", threw)
        }
    }

    @Test
    fun `every real signature survives the DER round trip`() {
        // r and s straddle the sign-bit boundary at random, so one signature exercises one
        // case. Hundreds make sure both 32- and 33-byte mpints, and short (leading-zero)
        // scalars, are all seen -- each is a different code path through the encoder.
        val kp = KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        val sizes = mutableSetOf<Int>()
        repeat(400) { n ->
            val sig = Signature.getInstance("SHA256withECDSA").apply { initSign(kp.private) }
            sig.update(byteArrayOf(n.toByte(), (n shr 8).toByte()))
            val der = sig.sign()
            val (r, s) = SshSig.derToRs(der)
            assertEquals("re-encoding is identical", der.toList(), derEncode(r, s).toList())
            sizes += r.toByteArray().size
        }
        assertTrue("saw a 33-byte (sign-padded) r: $sizes", 33 in sizes)
        assertTrue("saw a 32-byte r: $sizes", 32 in sizes)
    }

    @Test
    fun `a different message produces a different signature`() {
        val kp = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        fun sign(m: ByteArray) = Signature.getInstance("SHA256withECDSA").run {
            initSign(kp.private); update(m); sign()
        }
        assertNotEquals(
            Base64.getEncoder().encodeToString(sign("a".toByteArray())),
            Base64.getEncoder().encodeToString(sign("b".toByteArray()))
        )
    }

    /**
     * Emit real artifacts so an INDEPENDENT verifier can check them. A structural test
     * can be satisfied by bytes no real SSH implementation accepts, so this is what
     * actually closes the loop.
     */
    @Test
    fun `emit artifacts for external verification`() {
        val out = File("build/sshcheck").apply { mkdirs() }
        val kp = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val pub = kp.public as ECPublicKey

        File(out, "test.pub").writeText(SshSig.authorizedKeyLine(pub, "sudostamp-test") + "\n")
        val msg = "sudostamp format check\n".toByteArray()
        File(out, "msg.bin").writeBytes(msg)
        val der = Signature.getInstance("SHA256withECDSA").run {
            initSign(kp.private); update(msg); sign()
        }
        File(out, "sig.bin").writeBytes(SshSig.signatureBlob(der))

        assertTrue(File(out, "test.pub").length() > 0)
        assertTrue(File(out, "sig.bin").length() > 0)
    }

    // ------------------------------------------------------------------ helpers

    private fun readU32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
                ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    /** Minimal DER SEQUENCE { INTEGER r, INTEGER s } encoder, for round-trip testing. */
    private fun derEncode(r: BigInteger, s: BigInteger): ByteArray {
        fun intBytes(v: BigInteger): ByteArray {
            val b = v.toByteArray()          // already minimal + sign-correct
            return byteArrayOf(0x02, b.size.toByte()) + b
        }
        val body = intBytes(r) + intBytes(s)
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
