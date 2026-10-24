package com.ritwick.sudostamp

import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * Pairing: how a computer learns the key this phone made FOR IT, and the address to reach it
 * at, without trusting the network.
 *
 * The danger it answers: anything that can answer at the phone's address during setup (an
 * impostor, or a man in the middle) could hand the computer ITS key instead, and the computer
 * would pin it. A short code is easy to compare but, naively, easy to forge: an impostor could
 * generate keys until one gives the same 6 digits. So this is numeric comparison with a
 * COMMITMENT (as in Bluetooth Secure Simple Pairing, ZRTP, Vaudenay's SAS-MCA):
 *
 *   computer -> phone     pair-commit-v2(label)
 *   phone                 makes a NEW key K for this computer; Np: 32 random bytes;
 *                         D: the address and port the computer dialled, as the phone saw it;
 *                         S: the address the computer should keep (see Net.stableAddress)
 *   phone    -> computer  c = H(commit-tag || K || Np || D || S)
 *   computer -> phone     pair-reveal-v2(Nh)                    Nh: 32 random bytes
 *   phone    -> computer  K, Np, D, S                           computer checks c, and that
 *                                                               D is the address IT dialled
 *   both show             code = H(code-tag || K || Np || Nh || D || S) as 6 digits
 *
 * The phone is bound to (K, Np, D, S) before it sees Nh, and the computer picks Nh before it
 * sees Np. Someone in the middle must commit to its own values before learning Nh, and must
 * hand the real phone an Nh'' before learning Np: the codes then match by chance, one time in
 * a million. The person TYPES the phone's code into the computer, so it is really compared.
 *
 * D closes the relay that version 1 left open: a device that answered discovery first and
 * passed every byte through unchanged got the real key pinned, but with ITS OWN address in
 * sudo's configuration -- a permanent man in the middle. Now the computer refuses unless the
 * address the phone saw itself being dialled on is the address the computer dialled.
 *
 * One key per computer: a signature made for one computer is useless on another, and the
 * approval screen names the computer that owns the key, so a request relayed from elsewhere
 * cannot borrow a familiar name. Nothing secret is exchanged: K is public and the nonces are
 * single-use. Pairing never signs anything and is not on the sudo path.
 *
 * All fields are SSH strings (length-prefixed), so no two different inputs hash the same.
 */
object Pairing {

    /** ssh-agent extension names (SSH_AGENTC_EXTENSION, draft-miller-ssh-agent §3.8).
     *  Version 2: version 1 (one key for every computer, no address binding) is refused. */
    const val EXT_COMMIT = "pair-commit-v2@sudostamp"
    const val EXT_REVEAL = "pair-reveal-v2@sudostamp"
    const val EXT_DONE = "pair-done-v2@sudostamp"

    const val NONCE_BYTES = 32
    const val CODE_DIGITS = 6

    /** An endpoint on the wire: 16 address bytes (IPv4 as ::ffff:a.b.c.d) and a 2-byte port. */
    const val ENDPOINT_BYTES = 18

    /** How long one arming lasts: the code on screen, and the window in which a second
     *  computer's attempt cancels a pairing that just finished. */
    const val CODE_TTL_MS = 120_000L

    private val COMMIT_TAG = "sudostamp-pair-commit-v2\u0000".toByteArray(Charsets.US_ASCII)
    private val CODE_TAG = "sudostamp-pair-code-v2\u0000".toByteArray(Charsets.US_ASCII)

    fun commitment(keyBlob: ByteArray, phoneNonce: ByteArray, dialled: ByteArray, stable: ByteArray): ByteArray =
        sha256(COMMIT_TAG, keyBlob, phoneNonce, dialled, stable)

    /** The 6-digit code, zero-padded. The first 8 hash bytes as an unsigned number mod 10^6:
     *  the bias from 2^64 not being a multiple of 10^6 is below 10^-13. */
    fun code(keyBlob: ByteArray, phoneNonce: ByteArray, hostNonce: ByteArray, dialled: ByteArray, stable: ByteArray): String {
        val h = sha256(CODE_TAG, keyBlob, phoneNonce, hostNonce, dialled, stable)
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (h[i].toLong() and 0xFF)
        return java.lang.Long.remainderUnsigned(v, 1_000_000L).toString().padStart(CODE_DIGITS, '0')
    }

    /** "482913" -> "482 913", the way both screens show it. */
    fun spaced(code: String): String = code.substring(0, 3) + " " + code.substring(3)

    /**
     * The computer's name as shown on the phone: printable ASCII only, at most 64 characters.
     * It comes off the network, so it is display text and nothing more.
     */
    fun cleanLabel(raw: ByteArray): String =
        String(raw, Charsets.US_ASCII).filter { it in ' '..'~' }.trim().take(64).ifEmpty { "a computer" }

    /** Tag, then each part as an SSH string. */
    private fun sha256(tag: ByteArray, vararg parts: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(tag)
        for (p in parts) {
            o.write(byteArrayOf((p.size ushr 24).toByte(), (p.size ushr 16).toByte(), (p.size ushr 8).toByte(), p.size.toByte()))
            o.write(p)
        }
        return MessageDigest.getInstance("SHA-256").digest(o.toByteArray())
    }
}
