package com.ritwick.sudostamp

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * The Keystore keys, one per paired computer (see [Hosts]). THIS IS THE WHOLE SECURITY MODEL.
 *
 * Created with setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG). A timeout of
 * ZERO means "a fresh biometric is required for EVERY use" -- not a window, not once per
 * session. The TEE enforces it, which is what makes this a hard gate rather than a prompt:
 *
 *   - No code path in this app can produce a signature without a fingerprint.
 *   - Malware on the phone cannot either, even calling Keystore directly.
 *   - The key is non-exportable; it cannot be copied off the device.
 *
 * Deliberately NOT done:
 *   - No software key. Keystore falls back to software where the hardware is missing, and
 *     then every promise above is void; [create] checks where the key really landed and
 *     refuses one outside secure hardware (except in a debug build, for the emulator).
 *   - No validity window. A window would let one touch cover many approvals.
 *   - No survival across fingerprint enrollment. Enrolling a new finger destroys the keys,
 *     so anyone who learns the phone's PIN cannot add their own finger and approve.
 */
object Keys {

    /** The one key of versions before 1.4 (now [Hosts.LEGACY_ID]). */
    const val LEGACY_ALIAS = "sudostamp-v1"
    private const val PREFIX = "sudostamp-h-"
    private const val PROVIDER = "AndroidKeyStore"

    fun aliasFor(hostId: String) = if (hostId == Hosts.LEGACY_ID) LEGACY_ALIAS else PREFIX + hostId

    /** A fresh random id for a new computer's key. */
    fun newId(): String = ByteArray(8).also { SecureRandom().nextBytes(it) }
        .joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private fun store(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    fun exists(alias: String): Boolean = runCatching { store().containsAlias(alias) }.getOrDefault(false)

    /** Every per-computer alias in the Keystore, whether or not a computer still owns it. */
    fun pairingAliases(): List<String> =
        runCatching { store().aliases().toList().filter { it.startsWith(PREFIX) } }.getOrDefault(emptyList())

    enum class State { MISSING, READY, INVALIDATED }

    /**
     * Whether a key can still sign. A key invalidated by a fingerprint enrollment still
     * EXISTS -- its alias and public key are intact -- but every initSign throws, so the
     * agent would answer FAILURE to every sudo from that computer.
     *
     * Each call starts (and abandons) a Keystore operation, so it is checked on resume, not
     * on every screen update: Keystore prunes old operations, and a flood of them must not be
     * able to evict the one a pending approval holds.
     */
    fun state(alias: String): State {
        if (!exists(alias)) return State.MISSING
        return try {
            newSigner(alias)
            State.READY
        } catch (e: KeyPermanentlyInvalidatedException) {
            State.INVALIDATED
        } catch (e: Exception) {
            State.READY   // anything else is transient; a real sign attempt will say so
        }
    }

    fun publicKey(alias: String): ECPublicKey {
        val c = store().getCertificate(alias) ?: error("no key $alias")
        return c.publicKey as ECPublicKey
    }

    /** The SSH public key blob of [alias], or null if it is gone. */
    fun blob(alias: String): ByteArray? = runCatching { SshSig.keyBlob(publicKey(alias)) }.getOrNull()

    /**
     * Create [alias]. Tries StrongBox (a dedicated secure element) first and falls back to
     * the TEE; both enforce biometric-per-use, StrongBox is only a stronger container.
     * Returns which one the key is really in, read back from the key itself. Throws if it is
     * in neither and [allowSoftware] is false.
     */
    fun create(alias: String, allowSoftware: Boolean): String {
        try {
            generate(alias, strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generate(alias, strongBox = false)
        }
        val where = container(alias)
        if (where == null && !allowSoftware) {
            delete(alias)
            throw IllegalStateException("this phone's Keystore put the key in software, not secure hardware")
        }
        return where ?: "software"
    }

    private fun generate(alias: String, strongBox: Boolean) {
        val g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        val b = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            // Every signature needs a fresh biometric. NOT a time window.
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            // The platform default, stated so it cannot silently change: a new finger
            // enrolled on the phone kills the key rather than inheriting its authority.
            .setInvalidatedByBiometricEnrollment(true)
            .setRandomizedEncryptionRequired(false)   // signing only

        if (strongBox) b.setIsStrongBoxBacked(true)

        g.initialize(b.build())
        g.generateKeyPair()
    }

    /** "StrongBox" or "TEE" for a key in secure hardware, null for a software key. */
    @Suppress("DEPRECATION")   // isInsideSecureHardware: the only test on API 30
    private fun container(alias: String): String? {
        val pk = store().getKey(alias, null) as PrivateKey
        val info = KeyFactory.getInstance(pk.algorithm, PROVIDER).getKeySpec(pk, KeyInfo::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> "secure hardware"
                else -> null
            }
        }
        return if (info.isInsideSecureHardware) "secure hardware" else null
    }

    /**
     * A Signature initialised with the private key, ready to be wrapped in a CryptoObject.
     * Only after a successful biometric does sign() succeed; calling it earlier throws,
     * because the TEE refuses. That failure is intentionally NOT swallowed.
     */
    fun newSigner(alias: String): Signature {
        val pk = store().getKey(alias, null) as? PrivateKey ?: error("no private key $alias")
        return Signature.getInstance("SHA256withECDSA").apply { initSign(pk) }
    }

    fun delete(alias: String) {
        val ks = store()
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }
}
