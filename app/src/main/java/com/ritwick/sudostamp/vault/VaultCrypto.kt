package com.ritwick.sudostamp.vault

import com.ritwick.sudostamp.Hpke
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/**
 * Every refusal of this module, and the only exception it throws. One type on purpose: a caller
 * (the vault process, phase 1c) ends every one of them the same way, and the fuzz test checks
 * that nothing else -- no IllegalArgumentException from Base64, no BadPaddingException from the
 * provider -- ever escapes. [reason] is for logs and tests, never shown to a computer.
 */
class VaultRefused(val reason: String) : Exception(reason)

/**
 * A Bitwarden symmetric key: AES-256 encryption key (32 bytes) || HMAC-SHA256 key (32 bytes).
 * The user key, the org key, an item key and the stretched master key all have this shape.
 *
 * Takes ownership of [bytes] (no copy, so there is exactly one array to wipe). The platform's
 * SecretKeySpec copies the key into an object nobody can zero; that copy lives only for one
 * Cipher/Mac init and is the price of platform primitives.
 */
class SymmetricKey(bytes: ByteArray) {
    private val raw: ByteArray = bytes

    init {
        if (bytes.size != SIZE) {
            bytes.fill(0)
            throw VaultRefused("symmetric key of ${bytes.size} bytes")
        }
    }

    internal fun aes() = SecretKeySpec(raw, 0, 32, "AES")
    internal fun macKey(): ByteArray = raw.copyOfRange(32, 64)

    /** A copy for the caller to compare or re-wrap; the caller wipes it. */
    fun copyBytes(): ByteArray = raw.copyOf()

    fun wipe() = raw.fill(0)

    companion object {
        const val SIZE = 64
    }
}

/** The account's RSA private key as PKCS#8 DER, so it can be zeroed. A PrivateKey object is made
 *  from it only inside [VaultCrypto.unwrapOrgKey] and dropped there. */
class VaultPrivateKey internal constructor(private val der: ByteArray) {
    internal fun bytes(): ByteArray = der
    fun wipe() = der.fill(0)
}

/**
 * An EncString, parsed strictly. Only the two V1 types exist here (docs/design/vault-grant.md
 * section 6.3): a V2 account, a legacy MAC-less type 0, or anything new is refused at parse time,
 * independently of the server's own client-version gate.
 */
sealed class EncString {
    /** Type 2: AES-256-CBC + HMAC-SHA256, "2.iv|ct|mac". */
    class AesCbcHmac internal constructor(val iv: ByteArray, val ct: ByteArray, val mac: ByteArray) : EncString() {
        override fun encode() = "2.${b64(iv)}|${b64(ct)}|${b64(mac)}"
    }

    /** Type 4: RSA-2048-OAEP-SHA1, "4.ct". */
    class RsaOaepSha1 internal constructor(val ct: ByteArray) : EncString() {
        override fun encode() = "4.${b64(ct)}"
    }

    abstract fun encode(): String

    companion object {
        /** Longer than any field the server stores (its own cap is 10 000 characters for notes); a
         *  bound on the work a hostile sync can make the parser do. */
        const val MAX_CHARS = 1 shl 16
        const val IV_BYTES = 16
        const val MAC_BYTES = 32
        const val RSA_BYTES = 256

        fun parse(s: String): EncString {
            if (s.length > MAX_CHARS) throw VaultRefused("EncString too long")
            val dot = s.indexOf('.')
            // Exactly one digit and a dot. Bitwarden's legacy form without a type ("iv|ct") is
            // type 0, AES-CBC without a MAC, and is refused with every other type.
            if (dot != 1) throw VaultRefused("EncString without a type")
            val body = s.substring(2)
            return when (s[0]) {
                '2' -> {
                    val parts = body.split('|')
                    if (parts.size != 3) throw VaultRefused("type 2 needs 3 parts, got ${parts.size}")
                    val iv = unb64(parts[0])
                    val ct = unb64(parts[1])
                    val mac = unb64(parts[2])
                    if (iv.size != IV_BYTES) throw VaultRefused("iv of ${iv.size} bytes")
                    if (mac.size != MAC_BYTES) throw VaultRefused("mac of ${mac.size} bytes")
                    if (ct.isEmpty() || ct.size % 16 != 0) throw VaultRefused("ciphertext of ${ct.size} bytes")
                    AesCbcHmac(iv, ct, mac)
                }
                '4' -> {
                    if (body.contains('|')) throw VaultRefused("type 4 has one part")
                    val ct = unb64(body)
                    if (ct.size != RSA_BYTES) throw VaultRefused("RSA ciphertext of ${ct.size} bytes")
                    RsaOaepSha1(ct)
                }
                else -> throw VaultRefused("EncString type ${s[0]} refused")
            }
        }

        internal fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)

        /** Strict standard base64: padded, canonical (re-encodes to the same text), no
         *  whitespace. Java's decoder alone accepts missing padding and non-zero trailing bits. */
        internal fun unb64(s: String): ByteArray {
            if (s.isEmpty()) throw VaultRefused("empty base64")
            val b = try {
                Base64.getDecoder().decode(s)
            } catch (e: IllegalArgumentException) {
                throw VaultRefused("bad base64")
            }
            if (b64(b) != s) throw VaultRefused("non-canonical base64")
            return b
        }
    }
}

/**
 * Bitwarden V1 client crypto, from platform primitives only (docs/design/vault-grant.md section
 * 7): the KDF, the login hash, EncString types 2 and 4, unwrapping the user, private and org keys,
 * and re-wrapping an item key for the org. No new construction: this is the published client
 * format, checked against an independent pyca implementation (tools/test/vault_vectors.py and
 * tools/verify_vault_crypto.py) and Bitwarden's published master-password-hash vector.
 *
 * Every key is a ByteArray (or wraps one) with a wipe; nothing secret becomes a String, because a
 * String can never be zeroed.
 */
object VaultCrypto {

    const val KDF_PBKDF2 = 0
    /** OWASP's and Bitwarden's default floor. Lower is refused: the owner's account already uses it. */
    const val MIN_ITERATIONS = 600_000
    /** Bitwarden's own maximum for PBKDF2. Above it a hostile server could only make the phone spin. */
    const val MAX_ITERATIONS = 2_000_000

    private val random = SecureRandom()

    /**
     * Master key = PBKDF2-HMAC-SHA256(password, lowercased trimmed email, iterations), 32 bytes.
     * Refuses Argon2id (type 1, no platform implementation) and anything but [KDF_PBKDF2], and an
     * iteration count outside [MIN_ITERATIONS]..[MAX_ITERATIONS], before doing any work.
     */
    fun masterKey(password: CharArray, email: String, kdfType: Int, iterations: Int): ByteArray {
        if (kdfType != KDF_PBKDF2) throw VaultRefused("KDF type $kdfType refused")
        if (iterations < MIN_ITERATIONS) throw VaultRefused("$iterations iterations is under $MIN_ITERATIONS")
        if (iterations > MAX_ITERATIONS) throw VaultRefused("$iterations iterations is over $MAX_ITERATIONS")
        return pbkdf2(password, email, iterations)
    }

    /** [masterKey] without the floor: for Bitwarden's published vector (100 000 iterations) only. */
    internal fun pbkdf2(password: CharArray, email: String, iterations: Int): ByteArray {
        // The provider turns the chars into UTF-8 itself. A lone surrogate has no UTF-8 form and
        // providers disagree on what to make of one (JS clients write U+FFFD): refuse instead.
        utf8(password).fill(0)
        val salt = email.trim().lowercase(Locale.ROOT).toByteArray(Charsets.UTF_8)
        val spec = PBEKeySpec(password, salt, iterations, 256)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } catch (e: GeneralSecurityException) {
            throw VaultRefused("PBKDF2 failed")
        } finally {
            spec.clearPassword()
        }
    }

    /**
     * The login credential: base64(PBKDF2-HMAC-SHA256(masterKey, salt = password, 1 iteration)).
     *
     * Computed as the single HMAC it is (one iteration, one 32-byte block: T1 = HMAC(P, S ||
     * INT(1))): PBEKeySpec takes the password as chars and UTF-8-encodes them, so raw key bytes
     * cannot be passed through SecretKeyFactory. A String because it is a form field on the wire,
     * and it is not a key (it decrypts nothing).
     */
    fun masterPasswordHash(masterKey: ByteArray, password: CharArray): String {
        if (masterKey.size != 32) throw VaultRefused("master key of ${masterKey.size} bytes")
        val pw = utf8(password)
        val block = pw + byteArrayOf(0, 0, 0, 1)
        pw.fill(0)
        val h = Hpke.hmac(masterKey, block)
        block.fill(0)
        return EncString.b64(h).also { h.fill(0) }
    }

    /** Stretched master key = HKDF-Expand(masterKey, "enc", 32) || HKDF-Expand(masterKey, "mac", 32). */
    fun stretch(masterKey: ByteArray): SymmetricKey {
        if (masterKey.size != 32) throw VaultRefused("master key of ${masterKey.size} bytes")
        val enc = Hpke.expand(masterKey, "enc".toByteArray(Charsets.US_ASCII), 32)
        val mac = Hpke.expand(masterKey, "mac".toByteArray(Charsets.US_ASCII), 32)
        return SymmetricKey(enc + mac).also { enc.fill(0); mac.fill(0) }
    }

    /** The user key: a type 2 under the stretched master key, exactly 64 bytes. */
    fun decryptUserKey(encUserKey: String, stretched: SymmetricKey): SymmetricKey =
        SymmetricKey(decrypt(EncString.parse(encUserKey), stretched))

    /** The account's RSA private key: a type 2 under the user key, PKCS#8 DER of an RSA-2048 key. */
    fun decryptPrivateKey(encPrivateKey: String, userKey: SymmetricKey): VaultPrivateKey {
        val der = decrypt(EncString.parse(encPrivateKey), userKey)
        try {
            val k = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(der))
            if (k !is RSAPrivateCrtKey || k.modulus.bitLength() != 2048) throw VaultRefused("not an RSA-2048 key")
        } catch (e: GeneralSecurityException) {
            der.fill(0)
            throw VaultRefused("private key is not PKCS#8 RSA")
        } catch (e: RuntimeException) {
            // A provider may throw an unchecked exception on odd DER: still a refusal.
            der.fill(0)
            throw VaultRefused("private key is not PKCS#8 RSA")
        } catch (e: VaultRefused) {
            der.fill(0)
            throw e
        }
        return VaultPrivateKey(der)
    }

    /**
     * The org key: a type 4 under the private key, exactly 64 bytes. OAEP is spelled out (SHA-1 and
     * MGF1-SHA-1, Bitwarden's), never the provider's default for "OAEPPadding".
     */
    fun unwrapOrgKey(encOrgKey: String, privateKey: VaultPrivateKey): SymmetricKey {
        val e = EncString.parse(encOrgKey) as? EncString.RsaOaepSha1 ?: throw VaultRefused("org key is not type 4")
        val pt = try {
            val k = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(privateKey.bytes()))
            Cipher.getInstance("RSA/ECB/OAEPPadding").run {
                init(Cipher.DECRYPT_MODE, k, OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT))
                doFinal(e.ct)
            }
        } catch (x: GeneralSecurityException) {
            throw VaultRefused("RSA-OAEP refused")
        } catch (x: RuntimeException) {
            throw VaultRefused("RSA-OAEP refused")
        }
        return SymmetricKey(pt)
    }

    /**
     * Decrypts a type 2 under [key]. The MAC over iv || ct is checked first, in constant time, and
     * nothing is decrypted unless it matches (encrypt-then-MAC: a padding oracle needs the decrypt
     * to run on a forged ciphertext).
     */
    fun decrypt(e: EncString, key: SymmetricKey): ByteArray {
        if (e !is EncString.AesCbcHmac) throw VaultRefused("not type 2")
        val mk = key.macKey()
        val want = Hpke.hmac(mk, e.iv + e.ct)
        mk.fill(0)
        if (!macEqual(want, e.mac)) throw VaultRefused("MAC mismatch")
        return try {
            Cipher.getInstance("AES/CBC/PKCS5Padding").run {
                init(Cipher.DECRYPT_MODE, key.aes(), IvParameterSpec(e.iv))
                doFinal(e.ct)
            }
        } catch (x: GeneralSecurityException) {
            throw VaultRefused("AES-CBC refused")
        }
    }

    private fun macEqual(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    fun decrypt(s: String, key: SymmetricKey): ByteArray = decrypt(EncString.parse(s), key)

    /** Encrypts as type 2 under [key] with a fresh random IV. */
    fun encrypt(pt: ByteArray, key: SymmetricKey): EncString.AesCbcHmac =
        encryptWith(ByteArray(EncString.IV_BYTES).also { random.nextBytes(it) }, pt, key)

    internal fun encryptWith(iv: ByteArray, pt: ByteArray, key: SymmetricKey): EncString.AesCbcHmac {
        if (iv.size != EncString.IV_BYTES) throw VaultRefused("iv of ${iv.size} bytes")
        val ct = try {
            Cipher.getInstance("AES/CBC/PKCS5Padding").run {
                init(Cipher.ENCRYPT_MODE, key.aes(), IvParameterSpec(iv))
                doFinal(pt)
            }
        } catch (x: GeneralSecurityException) {
            throw VaultRefused("AES-CBC failed")
        }
        val mk = key.macKey()
        val mac = Hpke.hmac(mk, iv + ct)
        mk.fill(0)
        return EncString.AesCbcHmac(iv.copyOf(), ct, mac)
    }

    /**
     * Moves an item key from the user to the org (section 7: re-wrap, never re-encrypt the
     * fields): decrypt the type 2 item key under the user key (it must be 64 bytes), encrypt it
     * under the org key. The plain item key is zeroed before returning.
     */
    fun rewrapItemKey(encItemKey: String, userKey: SymmetricKey, orgKey: SymmetricKey): EncString.AesCbcHmac {
        val ik = SymmetricKey(decrypt(EncString.parse(encItemKey), userKey))
        val raw = ik.copyBytes()
        try {
            return encrypt(raw, orgKey)
        } finally {
            raw.fill(0)
            ik.wipe()
        }
    }

    fun wipe(vararg arrays: ByteArray) = arrays.forEach { it.fill(0) }

    /** The password as UTF-8, refusing malformed UTF-16 (a lone surrogate). The caller zeroes it. */
    private fun utf8(password: CharArray): ByteArray {
        val enc = Charsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val bb: ByteBuffer = try {
            enc.encode(CharBuffer.wrap(password))
        } catch (e: CharacterCodingException) {
            throw VaultRefused("password is not valid UTF-16")
        }
        val out = ByteArray(bb.remaining())
        bb.get(out)
        if (bb.hasArray()) bb.array().fill(0)
        return out
    }
}
