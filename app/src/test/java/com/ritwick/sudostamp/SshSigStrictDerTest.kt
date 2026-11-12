package com.ritwick.sudostamp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * SshSig.derToRs claims to be strict ("fails loudly on anything else"). Strict means DER as a
 * signer writes it: shortest lengths, non-negative INTEGERs with no needless 0x00, and r and s
 * inside the group (1..n-1). A reader that takes more turns a damaged signature into a plausible
 * one -- a 33-byte INTEGER over 2^256 became a mpint of 34 bytes -- which is exactly the kind of
 * failure that surfaces only at the sudo prompt. The Keystore never produces any of these, so
 * this is hardening, not a live attack.
 */
class SshSigStrictDerTest {

    private val N = Der.N

    @Test
    fun `what the DER reader accepts is exactly canonical DER with scalars below the order`() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val valid = (0 until 16).map { i ->
            Signature.getInstance("SHA256withECDSA").apply { initSign(kp.private); update(byteArrayOf(i.toByte())) }.sign()
        }
        Fuzz.run("der/strict", 14) { _, rnd ->
            val input = Der.damaged(rnd, valid[rnd.nextInt(valid.size)])
            val (r, s) = try {
                SshSig.derToRs(input)
            } catch (e: IllegalArgumentException) {
                return@run
            }
            assertTrue("r and s must be in 1..n-1: ${r.toString(16)} ${s.toString(16)}", r.signum() > 0 && s.signum() > 0 && r < N && s < N)
            assertArrayEquals("accepted input must be the canonical DER of what it returned", Der.encode(r, s), input)
        }
    }

    @Test
    fun `near misses a lenient reader takes are refused`() {
        val one = Der.int(BigInteger.ONE)
        val shapes = listOf(
            "33-byte INTEGER over 2^256" to Der.seq(byteArrayOf(0x02, 0x21, 0x05) + ByteArray(32) + one),
            "negative INTEGER (top bit set, no pad)" to Der.seq(byteArrayOf(0x02, 0x20, 0x80.toByte()) + ByteArray(31) + one),
            "non-minimal INTEGER (needless 0x00)" to Der.seq(byteArrayOf(0x02, 0x02, 0x00, 0x01) + one),
            "non-minimal long-form length" to byteArrayOf(0x30, 0x81.toByte(), 0x06) + one + one,
            "two-byte length where one suffices" to byteArrayOf(0x30, 0x82.toByte(), 0x00, 0x06) + one + one,
            "r equal to the group order" to Der.encode(N, BigInteger.ONE),
            "s above the group order" to Der.encode(BigInteger.ONE, N.add(BigInteger.ONE)),
        )
        for ((name, input) in shapes) {
            val threw = try { SshSig.derToRs(input); false } catch (e: IllegalArgumentException) { true }
            assertTrue("must reject $name", threw)
        }
        // And the extremes that are valid stay valid.
        for (v in listOf(BigInteger.ONE, N.subtract(BigInteger.ONE), BigInteger.ONE.shiftLeft(255), BigInteger.valueOf(0x80))) {
            SshSig.derToRs(Der.encode(v, v))
        }
    }
}
