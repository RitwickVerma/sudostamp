package com.ritwick.sudostamp

import java.security.MessageDigest

/**
 * Pairing: how a computer learns this phone's public key without trusting the network.
 *
 * The danger it answers: anything that can answer at the phone's address during setup (an
 * impostor, or a man in the middle) could hand the computer ITS key instead, and the
 * computer would pin it. Comparing a 43-character fingerprint by eye stops that in theory and
 * not in practice. A short code is easy to compare but, naively, easy to forge: the phone's
 * public key is public, so an impostor could generate keys until one gives the same 6 digits.
 *
 * So this is numeric comparison with a COMMITMENT (the method Bluetooth Secure Simple
 * Pairing and ZRTP use):
 *
 *   computer -> phone   pair-commit(label)
 *   phone    -> computer  c = H(commit-tag || key || Np)        Np: 32 random bytes
 *   computer -> phone   pair-reveal(Nh)                       Nh: 32 random bytes
 *   phone    -> computer  key, Np                             computer checks c
 *   both show           code = H(code-tag || key || Np || Nh) as 6 digits
 *
 * The phone is bound to (key, Np) before it sees Nh, and the computer picks Nh before it sees
 * Np. Someone in the middle must commit to its own (key', Np') before learning the
 * computer's Nh, and must hand the real phone an Nh'' before learning the phone's Np. Neither
 * code is then under its control: they match by chance, one time in a million, and a mismatch
 * is visible. The person TYPES the phone's code into the computer, so it is really compared.
 *
 * Nothing secret is exchanged: the key is public and the nonces are single-use. Pairing never
 * signs anything, and it is not on the sudo path at all -- pam_rssh never sends these
 * messages.
 */
object Pairing {

    /** ssh-agent extension names (SSH_AGENTC_EXTENSION, draft-miller-ssh-agent §3.8). */
    const val EXT_COMMIT = "pair-commit@sudostamp"
    const val EXT_REVEAL = "pair-reveal@sudostamp"
    const val EXT_DONE = "pair-done@sudostamp"

    const val NONCE_BYTES = 32
    const val CODE_DIGITS = 6

    /** How long a shown code stays on screen if nothing else happens. */
    const val CODE_TTL_MS = 120_000L

    private val COMMIT_TAG = "sudostamp-pair-commit-v1\u0000".toByteArray(Charsets.US_ASCII)
    private val CODE_TAG = "sudostamp-pair-code-v1\u0000".toByteArray(Charsets.US_ASCII)

    fun commitment(keyBlob: ByteArray, phoneNonce: ByteArray): ByteArray =
        sha256(COMMIT_TAG, keyBlob, phoneNonce)

    /** The 6-digit code, zero-padded. The first 8 hash bytes as an unsigned number mod 10^6:
     *  the bias from 2^64 not being a multiple of 10^6 is below 10^-13. */
    fun code(keyBlob: ByteArray, phoneNonce: ByteArray, hostNonce: ByteArray): String {
        val h = sha256(CODE_TAG, keyBlob, phoneNonce, hostNonce)
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

    private fun sha256(vararg parts: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").apply { parts.forEach { update(it) } }.digest()
}
