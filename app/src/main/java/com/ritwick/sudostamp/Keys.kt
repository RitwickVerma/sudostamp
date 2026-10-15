package com.ritwick.sudostamp

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * The Keystore key. THIS IS THE WHOLE SECURITY MODEL.
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
 *   - No silent downgrade to a software key if StrongBox is missing. TEE is fine, but
 *     the caller is TOLD which container it got instead of the app quietly weakening.
 *   - No validity window. A window would let one touch cover many approvals.
 *   - No survival across fingerprint enrollment. Enrolling a new finger destroys the key,
 *     so anyone who learns the phone's PIN cannot add their own finger and approve.
 */
object Keys {

    const val ALIAS = "sudostamp-v1"
    private const val PROVIDER = "AndroidKeyStore"

    private fun store(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    fun exists(): Boolean = runCatching { store().containsAlias(ALIAS) }.getOrDefault(false)

    enum class State { MISSING, READY, INVALIDATED }

    /**
     * Whether the key can still sign. A key invalidated by a fingerprint enrollment still
     * EXISTS -- its alias and public key are intact -- but every initSign throws, so the
     * agent answers FAILURE to every sudo. Without this check the setup screen kept saying
     * "listening" over a key that could never approve anything again.
     */
    fun state(): State {
        if (!exists()) return State.MISSING
        return try {
            newSigner()
            State.READY
        } catch (e: KeyPermanentlyInvalidatedException) {
            State.INVALIDATED
        } catch (e: Exception) {
            State.READY   // anything else is transient; a real sign attempt will say so
        }
    }

    fun publicKey(): ECPublicKey {
        val c = store().getCertificate(ALIAS) ?: error("no key: run setup first")
        return c.publicKey as ECPublicKey
    }

    /**
     * Create the key. Tries StrongBox (a dedicated secure element) first and falls back
     * to the TEE. Both enforce biometric-per-use; StrongBox is only a stronger container.
     * Returns a label describing which one we actually got.
     */
    fun create(): String = try {
        generate(strongBox = true)
    } catch (e: StrongBoxUnavailableException) {
        generate(strongBox = false)
    }

    private fun generate(strongBox: Boolean): String {
        val g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        val b = KeyGenParameterSpec.Builder(
            ALIAS,
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
        return if (strongBox) "StrongBox" else "TEE"
    }

    /**
     * A Signature initialised with the private key, ready to be wrapped in a CryptoObject.
     * Only after a successful biometric does sign() succeed; calling it earlier throws,
     * because the TEE refuses. That failure is intentionally NOT swallowed.
     */
    fun newSigner(): Signature {
        val pk = store().getKey(ALIAS, null) as? PrivateKey ?: error("no private key")
        return Signature.getInstance("SHA256withECDSA").apply { initSign(pk) }
    }

    fun delete() {
        val ks = store()
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS)
    }

    /** The authorized_keys line for pam_rssh's auth_key_file. */
    fun authorizedKeyLine(): String = SshSig.authorizedKeyLine(publicKey(), "sudostamp")
}
