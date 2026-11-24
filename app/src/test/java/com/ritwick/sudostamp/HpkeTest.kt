package com.ritwick.sudostamp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec

/**
 * Hpke against RFC 9180 Appendix A.3.1 (DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM,
 * base mode), sequence number 0 -- the only one this protocol ever uses. The cross-check against
 * pyca's own HPKE is tools/test/test_secret.py.
 */
class HpkeTest {

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private val info = hex("4f6465206f6e2061204772656369616e2055726e")
    private val skEm = hex("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb")
    private val pkEm = hex("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4")
    private val pkRm = hex("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0")
    private val pt = hex("4265617574792069732074727574682c20747275746820626561757479")
    private val aad0 = hex("436f756e742d30")
    private val ct0 = hex("5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434")

    private fun ephemeral(): KeyPair {
        val p256 = AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1")); getParameterSpec(ECParameterSpec::class.java)
        }
        val sk = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, skEm), p256))
        return KeyPair(Hpke.publicKey(pkEm), sk)
    }

    @Test
    fun `RFC 9180 A_3_1 base mode, sequence 0`() {
        val s = Hpke.sealWith(ephemeral(), pkRm, info, aad0, pt)
        assertArrayEquals(pkEm, s.enc)
        assertArrayEquals(ct0, s.ct)
    }

    @Test
    fun `info and aad are bound - changing either changes the ciphertext`() {
        val base = Hpke.sealWith(ephemeral(), pkRm, info, aad0, pt).ct
        assertNotEquals(base.toList(), Hpke.sealWith(ephemeral(), pkRm, info + 0, aad0, pt).ct.toList())
        assertNotEquals(base.toList(), Hpke.sealWith(ephemeral(), pkRm, info, aad0 + 0, pt).ct.toList())
    }

    /**
     * A sealed message for an INDEPENDENT opener: tools/verify_secret_seal.py opens it with pyca
     * (CI's android job, gate 2 of tools/verify.sh). Vectors prove the arithmetic; this proves
     * the phone's real seal() -- fresh key, longest value -- is something the computer can open.
     */
    @Test
    fun `emit a sealed message for external verification`() {
        val out = java.io.File("build/secretcheck").apply { mkdirs() }
        val pt = ByteArray(SecretProtocol.MAX_SECRET_BYTES).also { java.security.SecureRandom().nextBytes(it) }
        val inf = SecretProtocol.info("transcript".toByteArray())
        val s = Hpke.seal(pkRm, inf, ByteArray(0), pt)
        java.io.File(out, "pt.bin").writeBytes(pt)
        java.io.File(out, "info.bin").writeBytes(inf)
        java.io.File(out, "enc.bin").writeBytes(s.enc)
        java.io.File(out, "ct.bin").writeBytes(s.ct)
        assertEquals(pt.size + 16, java.io.File(out, "ct.bin").length().toInt())
    }

    @Test
    fun `seal uses a fresh ephemeral key every time`() {
        val a = Hpke.seal(pkRm, info, ByteArray(0), pt)
        val b = Hpke.seal(pkRm, info, ByteArray(0), pt)
        assertEquals(Hpke.POINT_BYTES, a.enc.size)
        assertEquals(pt.size + 16, a.ct.size)
        assertFalse(a.enc.contentEquals(b.enc))
    }

    @Test
    fun `recipient keys that are not a P-256 point are refused`() {
        val offCurve = pkRm.copyOf().also { it[64] = (it[64].toInt() xor 1).toByte() }
        val compressed = byteArrayOf(2) + pkRm.copyOfRange(1, 33)
        val tooLong = pkRm + 0
        val wrongPrefix = pkRm.copyOf().also { it[0] = 3 }
        // p itself as X: out of range even though it reduces to 0.
        val p = hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
        val xIsP = byteArrayOf(4) + p + pkRm.copyOfRange(33, 65)
        val zero = ByteArray(65).also { it[0] = 4 }
        for (bad in listOf(offCurve, compressed, tooLong, wrongPrefix, xIsP, zero, ByteArray(0))) {
            assertThrows(IllegalArgumentException::class.java) { Hpke.seal(bad, info, ByteArray(0), pt) }
        }
    }

    @Test
    fun `encode is the inverse of publicKey, with leading zero coordinates padded`() {
        assertArrayEquals(pkRm, Hpke.encode(Hpke.publicKey(pkRm)))
        assertArrayEquals(pkEm, Hpke.encode(Hpke.publicKey(pkEm)))
        // Neither vector has a short coordinate; about 1 key in 64 does. Find one.
        val g = java.security.KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        val short = generateSequence { g.generateKeyPair().public as java.security.interfaces.ECPublicKey }
            .take(5000).first { it.w.affineX.bitLength() <= 248 || it.w.affineY.bitLength() <= 248 }
        val e = Hpke.encode(short)
        assertEquals(Hpke.POINT_BYTES, e.size)
        assertEquals(short.w, Hpke.publicKey(e).w)
    }
}
