package com.ritwick.sudostamp

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.interfaces.ECPublicKey
import java.util.Base64

/**
 * SSH wire encoding for the two blobs pam_rssh needs.
 *
 * WHY THIS CLASS EXISTS: Android Keystore emits ECDSA signatures in DER
 * (SEQUENCE { INTEGER r, INTEGER s }), but the SSH agent protocol wants a nested
 * "string" of two mpints. A bug here produces signatures that look entirely
 * plausible and simply fail to verify on the server -- the worst kind of failure,
 * because it only shows up on real hardware at the moment you need it.
 *
 * The Java version of this logic was verified against real OpenSSH (`ssh-keygen -l`
 * parsed the key blob) and against an independent crypto library (the ECDSA signature
 * verified over the message). This port keeps the encoding identical; tools/verify_ssh_sig.py
 * still checks it.
 *
 * No cryptography happens here. Signing is done by the Keystore inside the TEE.
 */
object SshSig {

    const val KEY_TYPE = "ecdsa-sha2-nistp256"
    const val CURVE = "nistp256"

    // ---------------------------------------------------------------- encoding

    /** SSH "string": uint32 big-endian length, then the bytes. */
    private fun putString(out: ByteArrayOutputStream, s: ByteArray) {
        putUint32(out, s.size)
        out.write(s, 0, s.size)
    }

    private fun putUint32(out: ByteArrayOutputStream, v: Int) {
        out.write((v ushr 24) and 0xFF)
        out.write((v ushr 16) and 0xFF)
        out.write((v ushr 8) and 0xFF)
        out.write(v and 0xFF)
    }

    /**
     * Public key blob:  string "ecdsa-sha2-nistp256"
     *                   string "nistp256"
     *                   string Q        (uncompressed point: 0x04 || X || Y)
     */
    fun keyBlob(pub: ECPublicKey): ByteArray {
        val x = fixed(pub.w.affineX, 32)
        val y = fixed(pub.w.affineY, 32)
        val q = ByteArray(65)
        q[0] = 0x04
        System.arraycopy(x, 0, q, 1, 32)
        System.arraycopy(y, 0, q, 33, 32)

        val out = ByteArrayOutputStream(128)
        putString(out, KEY_TYPE.toByteArray(Charsets.US_ASCII))
        putString(out, CURVE.toByteArray(Charsets.US_ASCII))
        putString(out, q)
        return out.toByteArray()
    }

    /** A line suitable for pam_rssh's auth_key_file. */
    fun authorizedKeyLine(pub: ECPublicKey, comment: String? = null): String {
        val b64 = Base64.getEncoder().encodeToString(keyBlob(pub))
        return if (comment.isNullOrEmpty()) "$KEY_TYPE $b64" else "$KEY_TYPE $b64 $comment"
    }

    /**
     * Signature blob:  string "ecdsa-sha2-nistp256"
     *                  string ( string r, string s )
     *
     * [der] comes straight from java.security.Signature("SHA256withECDSA").
     */
    fun signatureBlob(der: ByteArray): ByteArray {
        val (r, s) = derToRs(der)
        val inner = ByteArrayOutputStream(80)
        putString(inner, mpint(r))
        putString(inner, mpint(s))

        val out = ByteArrayOutputStream(120)
        putString(out, KEY_TYPE.toByteArray(Charsets.US_ASCII))
        putString(out, inner.toByteArray())
        return out.toByteArray()
    }

    /** Left-pad or trim to exactly [len] bytes (curve coordinates are fixed-width). */
    private fun fixed(v: BigInteger, len: Int): ByteArray {
        val b = v.toByteArray()
        if (b.size == len) return b
        val out = ByteArray(len)
        if (b.size > len) {
            System.arraycopy(b, b.size - len, out, 0, len)   // drop leading zeros
        } else {
            System.arraycopy(b, 0, out, len - b.size, b.size)
        }
        return out
    }

    /**
     * mpint per RFC 4251: two's-complement, big-endian, minimal length, with a leading
     * 0x00 when the top bit is set so it is not read as negative.
     * BigInteger.toByteArray() already does exactly this.
     */
    private fun mpint(v: BigInteger): ByteArray = v.toByteArray()

    /**
     * Parse DER SEQUENCE { INTEGER r, INTEGER s }. Strict; fails loudly on anything else.
     *
     * Every read is bounds-checked and the lengths must account for every byte. The input
     * comes from the Keystore, so this is not an attack surface -- but a lenient parser
     * would turn a malformed signature into a plausible-looking wrong one, and that is
     * exactly the failure that only shows up at the sudo prompt.
     */
    fun derToRs(der: ByteArray): Pair<BigInteger, BigInteger> {
        var i = 0
        fun byte(): Int {
            require(i < der.size) { "DER truncated" }
            return der[i++].toInt() and 0xFF
        }
        fun length(): Int {
            val first = byte()
            if (first and 0x80 == 0) return first
            val n = first and 0x7F
            require(n in 1..2) { "bad DER length" }
            var len = 0
            repeat(n) { len = (len shl 8) or byte() }
            return len
        }

        require(byte() == 0x30) { "not a DER SEQUENCE" }
        val seqLen = length()
        require(i + seqLen == der.size) { "DER SEQUENCE length does not match its contents" }

        val parts = arrayOfNulls<BigInteger>(2)
        for (k in 0..1) {
            require(byte() == 0x02) { "expected INTEGER" }
            val len = length()
            // A P-256 scalar is at most 32 bytes, plus one 0x00 sign pad.
            require(len in 1..33) { "bad INTEGER length $len" }
            require(i + len <= der.size) { "DER truncated" }
            parts[k] = BigInteger(1, der.copyOfRange(i, i + len))
            i += len
        }
        require(i == der.size) { "trailing bytes after DER SEQUENCE" }

        val r = parts[0]!!
        val s = parts[1]!!
        require(r.signum() > 0 && s.signum() > 0) { "non-positive ECDSA component" }
        return r to s
    }
}
