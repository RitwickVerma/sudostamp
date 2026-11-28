package com.ritwick.sudostamp

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * HPKE (RFC 9180), base mode, single shot, ONE suite: DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 /
 * AES-128-GCM (0x0010 / 0x0001 / 0x0001). Seal only: the phone is always the sender.
 *
 * WHY COMPOSED HERE: the Android HPKE API is newer than minSdk 30, and the app takes no
 * third-party dependencies. Every primitive below is a platform one (ECDH, HMAC, AES-GCM); this
 * file is only the RFC's key schedule, line by line. It is checked against the RFC's own vectors
 * (Appendix A.3.1) and against pyca's independent implementation (tools/test/test_secret.py).
 * It is not a new construction, and nothing here may grow options: one suite, one mode, one message.
 */
object Hpke {

    /** An uncompressed P-256 point: 0x04 || X || Y. Both the recipient key and `enc`. */
    const val POINT_BYTES = 65

    private const val KEM_ID = 0x0010
    private const val KDF_ID = 0x0001
    private const val AEAD_ID = 0x0001
    private const val NK = 16       // AES-128 key
    private const val NN = 12       // GCM nonce
    private const val NH = 32       // SHA-256 output, and the DHKEM shared secret
    private const val TAG_BITS = 128

    private val VERSION = "HPKE-v1".toByteArray(Charsets.US_ASCII)
    private val KEM_SUITE = "KEM".toByteArray(Charsets.US_ASCII) + i2osp(KEM_ID, 2)
    private val HPKE_SUITE = "HPKE".toByteArray(Charsets.US_ASCII) + i2osp(KEM_ID, 2) + i2osp(KDF_ID, 2) + i2osp(AEAD_ID, 2)

    /** P-256 (secp256r1) domain parameters, from the platform rather than typed in. */
    private val P256: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }
    }

    class Sealed(val enc: ByteArray, val ct: ByteArray)

    /** Seals [pt] to [pkR] (a 65-byte uncompressed P-256 point) with a fresh ephemeral key.
     *  Throws IllegalArgumentException for a key that is not a point on the curve. */
    fun seal(pkR: ByteArray, info: ByteArray, aad: ByteArray, pt: ByteArray): Sealed {
        val g = KeyPairGenerator.getInstance("EC")
        g.initialize(ECGenParameterSpec("secp256r1"))
        return sealWith(g.generateKeyPair(), pkR, info, aad, pt)
    }

    /** [seal] with a given ephemeral key: for the RFC vectors only. */
    internal fun sealWith(eph: KeyPair, pkR: ByteArray, info: ByteArray, aad: ByteArray, pt: ByteArray): Sealed {
        val recipient = publicKey(pkR)
        val enc = encode(eph.public as ECPublicKey)
        // DHKEM Encap (RFC 9180 4.1).
        val dh = KeyAgreement.getInstance("ECDH").run {
            init(eph.private)
            doPhase(recipient, true)
            generateSecret()
        }
        require(dh.size == NH) { "ECDH output of ${dh.size} bytes" }
        val eaePrk = labeledExtract(KEM_SUITE, ByteArray(0), "eae_prk", dh)
        val shared = labeledExpand(KEM_SUITE, eaePrk, "shared_secret", enc + pkR, NH)
        dh.fill(0)
        // KeySchedule, mode_base (5.1): empty psk and psk_id.
        val pskIdHash = labeledExtract(HPKE_SUITE, ByteArray(0), "psk_id_hash", ByteArray(0))
        val infoHash = labeledExtract(HPKE_SUITE, ByteArray(0), "info_hash", info)
        val context = byteArrayOf(0) + pskIdHash + infoHash
        val secret = labeledExtract(HPKE_SUITE, shared, "secret", ByteArray(0))
        shared.fill(0)
        val key = labeledExpand(HPKE_SUITE, secret, "key", context, NK)
        val nonce = labeledExpand(HPKE_SUITE, secret, "base_nonce", context, NN)  // sequence 0: the base nonce
        secret.fill(0)
        val ct = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            updateAAD(aad)
            doFinal(pt)
        }
        key.fill(0)
        return Sealed(enc, ct)
    }

    /**
     * The public key in [b], which must be exactly 0x04 || X || Y with X, Y < p and the point on
     * P-256. Checked here, not left to the provider: an off-curve point is the classic invalid-curve
     * attack on ECDH, and not every provider has always refused one.
     */
    fun publicKey(b: ByteArray): ECPublicKey {
        require(b.size == POINT_BYTES && b[0] == 4.toByte()) { "not an uncompressed P-256 point" }
        val x = BigInteger(1, b.copyOfRange(1, 33))
        val y = BigInteger(1, b.copyOfRange(33, 65))
        require(onCurve(x, y)) { "not a point on P-256" }
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), P256)) as ECPublicKey
    }

    /** y² = x³ + ax + b (mod p), with both coordinates reduced. (0, 0) is not on P-256, and
     *  the point at infinity has no uncompressed encoding. */
    fun onCurve(x: BigInteger, y: BigInteger): Boolean {
        val p = (P256.curve.field as java.security.spec.ECFieldFp).p
        if (x.signum() < 0 || y.signum() < 0 || x >= p || y >= p) return false
        val lhs = y.multiply(y).mod(p)
        val rhs = x.multiply(x).multiply(x).add(P256.curve.a.multiply(x)).add(P256.curve.b).mod(p)
        return lhs == rhs
    }

    /** SerializePublicKey: 0x04 || X || Y, each coordinate left-padded to 32 bytes. */
    fun encode(k: ECPublicKey): ByteArray = byteArrayOf(4) + fixed(k.w.affineX) + fixed(k.w.affineY)

    private fun fixed(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        require(raw.size <= 33) { "coordinate too long" }
        val out = ByteArray(32)
        val src = if (raw.size == 33) raw.copyOfRange(1, 33) else raw
        System.arraycopy(src, 0, out, 32 - src.size, src.size)
        return out
    }

    private fun labeledExtract(suite: ByteArray, salt: ByteArray, label: String, ikm: ByteArray): ByteArray =
        extract(salt, VERSION + suite + label.toByteArray(Charsets.US_ASCII) + ikm)

    private fun labeledExpand(suite: ByteArray, prk: ByteArray, label: String, info: ByteArray, len: Int): ByteArray =
        expand(prk, i2osp(len, 2) + VERSION + suite + label.toByteArray(Charsets.US_ASCII) + info, len)

    /** HKDF-Extract (RFC 5869). An empty salt is HashLen zero bytes, which is what HMAC makes of
     *  an empty key anyway; spelled out because SecretKeySpec refuses an empty key. */
    private fun extract(salt: ByteArray, ikm: ByteArray): ByteArray =
        hmac(if (salt.isEmpty()) ByteArray(NH) else salt, ikm)

    /** HKDF-Expand for len ≤ HashLen: every length this suite asks for is one block. Internal, not
     *  private: vault/VaultCrypto.kt stretches the Bitwarden master key with it rather than with a
     *  second copy. */
    internal fun expand(prk: ByteArray, info: ByteArray, len: Int): ByteArray {
        require(len in 1..NH)
        return hmac(prk, info + byteArrayOf(1)).copyOf(len)
    }

    internal fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(data)
        }

    private fun i2osp(v: Int, n: Int) = ByteArray(n) { ((v ushr (8 * (n - 1 - it))) and 0xFF).toByte() }
}
