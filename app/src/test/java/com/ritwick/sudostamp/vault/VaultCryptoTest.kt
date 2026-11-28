package com.ritwick.sudostamp.vault

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.util.Base64

/**
 * The fixture tools/test/vault_vectors.py wrote with pyca (an implementation of the same published
 * format that shares no code with VaultCrypto). Every value is a plain string with no quote or
 * backslash, so a regex reads it: the app has no JSON library on the JVM (org.json is an Android
 * stub there), and the test takes no dependency for one.
 */
internal object VaultVectors {
    val v: Map<String, String> by lazy {
        val text = VaultVectors::class.java.getResourceAsStream("/vault/vectors-v1.json")!!.readBytes().toString(Charsets.US_ASCII)
        val m = Regex("\"([A-Za-z0-9]+)\": \"([^\"\\\\]*)\"").findAll(text).associate { it.groupValues[1] to it.groupValues[2] }
        // Every line but the braces is one entry: a value the regex skipped would be a silent gap.
        check(m.size == text.lines().count { it.trim().startsWith("\"") }) { "fixture not read whole" }
        m
    }

    operator fun get(k: String): String = v[k] ?: error("fixture has no $k")
    fun hex(k: String): ByteArray = get(k).let { s -> ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() } }

    val password: CharArray get() = get("password").toCharArray()

    /** 600 000 iterations take a moment: derived once for the whole class. */
    val masterKey: ByteArray by lazy {
        VaultCrypto.masterKey(password, get("email"), get("kdfType").toInt(), get("iterations").toInt())
    }
    val stretched: SymmetricKey get() = VaultCrypto.stretch(masterKey)
    val userKey: SymmetricKey get() = VaultCrypto.decryptUserKey(get("encUserKey"), stretched)
    val privateKey: VaultPrivateKey get() = VaultCrypto.decryptPrivateKey(get("encPrivateKey"), userKey)
    val orgKey: SymmetricKey get() = VaultCrypto.unwrapOrgKey(get("encOrgKey"), privateKey)
}

/**
 * VaultCrypto (Bitwarden V1 client crypto) against pyca's vectors, Bitwarden's own published
 * master-password-hash vector, and every refusal the design names (docs/design/vault-grant.md
 * sections 6.3 and 7). tools/verify_vault_crypto.py checks the other direction.
 *
 * Still owed (phase 2): vectors from the official `bw` CLI against a throwaway server.
 */
class VaultCryptoTest {
    private val f = VaultVectors

    private fun refused(reason: String? = null, block: () -> Unit) {
        try {
            block()
        } catch (e: VaultRefused) {
            if (reason != null) assertEquals(reason, e.reason)
            return
        }
        fail("not refused")
    }

    private fun b64(b: ByteArray) = Base64.getEncoder().encodeToString(b)

    // ---- derivation

    /**
     * Bitwarden's published vector (sdk-internal, bitwarden-crypto, master_key.rs
     * `test_password_hash_pbkdf2`): "asdfasdf" with "test@bitwarden.com" at 100 000 iterations, also
     * under the upper-case and space-prefixed spellings of the email. Below the 600 000 floor, so it
     * goes through the unchecked derivation; the floor has its own test. pyca reproduces it too
     * (tools/test/vault_vectors.py).
     */
    @Test
    fun `Bitwarden published master password hash vector`() {
        for (email in listOf("test@bitwarden.com", "TEST@bitwarden.com", " test@bitwarden.com")) {
            val mk = VaultCrypto.pbkdf2("asdfasdf".toCharArray(), email, 100_000)
            assertEquals("wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw=", VaultCrypto.masterPasswordHash(mk, "asdfasdf".toCharArray()))
        }
    }

    @Test
    fun `master key, login hash and stretched key match pyca`() {
        assertArrayEquals(f.hex("masterKey"), f.masterKey)
        assertEquals(f["masterPasswordHash"], VaultCrypto.masterPasswordHash(f.masterKey, f.password))
        assertArrayEquals(f.hex("stretchedKey"), f.stretched.copyBytes())
    }

    @Test
    fun `only PBKDF2 is accepted`() {
        for (t in listOf(1, 2, -1, 255)) refused("KDF type $t refused") { VaultCrypto.masterKey(f.password, f["email"], t, 600_000) }
    }

    @Test
    fun `iterations outside 600000 to 2000000 are refused before any work`() {
        for (n in listOf(599_999, 100_000, 5000, 1, 0, -1, Int.MIN_VALUE)) {
            refused("$n iterations is under 600000") { VaultCrypto.masterKey(f.password, f["email"], 0, n) }
        }
        for (n in listOf(2_000_001, Int.MAX_VALUE)) {
            refused("$n iterations is over 2000000") { VaultCrypto.masterKey(f.password, f["email"], 0, n) }
        }
    }

    @Test
    fun `a password with a lone surrogate is refused`() {
        refused("password is not valid UTF-16") { VaultCrypto.pbkdf2(charArrayOf('a', '\uD800', 'b'), "x@example.invalid", 1) }
        refused("password is not valid UTF-16") { VaultCrypto.masterPasswordHash(ByteArray(32), charArrayOf('\uDC00')) }
    }

    // ---- the key chain, as pyca built it

    @Test
    fun `user key, private key, org key and item fields decrypt as pyca encrypted them`() {
        val uk = f.userKey
        assertArrayEquals(f.hex("userKey"), uk.copyBytes())
        val pk = f.privateKey
        assertEquals(f["privateKeyDer"], b64(pk.bytes()))
        val ok = f.orgKey
        assertArrayEquals(f.hex("orgKey"), ok.copyBytes())
        val ik = SymmetricKey(VaultCrypto.decrypt(f["encItemKey"], uk))
        assertArrayEquals(f.hex("itemKey"), ik.copyBytes())
        assertEquals(f["itemName"], VaultCrypto.decrypt(f["encItemName"], ik).toString(Charsets.UTF_8))
        assertArrayEquals(f.hex("itemPassword"), VaultCrypto.decrypt(f["encItemPassword"], ik))
        assertEquals(f["userNotes"], VaultCrypto.decrypt(f["encUserNotes"], uk).toString(Charsets.UTF_8))
        assertEquals(f["orgText"], VaultCrypto.decrypt(f["encOrgText"], ok).toString(Charsets.UTF_8))
        assertEquals(0, VaultCrypto.decrypt(f["encEmpty"], uk).size)
    }

    @Test
    fun `an item key is re-wrapped under the org key and the item's fields still open`() {
        val ok = f.orgKey
        val re = VaultCrypto.rewrapItemKey(f["encItemKey"], f.userKey, ok)
        val ik = SymmetricKey(VaultCrypto.decrypt(re, ok))
        assertArrayEquals(f.hex("itemKey"), ik.copyBytes())
        assertEquals(f["itemName"], VaultCrypto.decrypt(f["encItemName"], ik).toString(Charsets.UTF_8))
        // The user key cannot open the re-wrapped key: it really moved.
        refused("MAC mismatch") { VaultCrypto.decrypt(re, f.userKey) }
    }

    @Test
    fun `keys of the wrong size or kind are refused`() {
        refused("symmetric key of 32 bytes") { VaultCrypto.decryptUserKey(f["encUserKeyShort"], f.stretched) }
        refused("symmetric key of 32 bytes") { VaultCrypto.unwrapOrgKey(f["encOrgKeyShort"], f.privateKey) }
        refused("not an RSA-2048 key") { VaultCrypto.decryptPrivateKey(f["encPrivateKey1024"], f.userKey) }
        // Bitwarden's OAEP is SHA-1 throughout; the same key wrapped with OAEP-SHA-256 must not open.
        refused("RSA-OAEP refused") { VaultCrypto.unwrapOrgKey(f["encOrgKeyOaepSha256"], f.privateKey) }
        refused("org key is not type 4") { VaultCrypto.unwrapOrgKey(f["encOrgText"], f.privateKey) }
        val shortItemKey = VaultCrypto.encrypt(ByteArray(32) { 7 }, f.userKey).encode()
        refused("symmetric key of 32 bytes") { VaultCrypto.rewrapItemKey(shortItemKey, f.userKey, f.orgKey) }
        refused("private key is not PKCS#8 RSA") { VaultCrypto.decryptPrivateKey(VaultCrypto.encrypt(ByteArray(40) { 1 }, f.userKey).encode(), f.userKey) }
        refused("master key of 31 bytes") { VaultCrypto.stretch(ByteArray(31)) }
        refused("symmetric key of 65 bytes") { SymmetricKey(ByteArray(65)) }
    }

    // ---- EncString: the MAC

    @Test
    fun `the MAC is checked before anything is decrypted`() {
        val good = EncString.parse(f["encItemName"]) as EncString.AesCbcHmac
        // Garbage ciphertext (padding would fail) with a wrong MAC: the refusal is the MAC's.
        val forged = "2.${b64(good.iv)}|${b64(ByteArray(32) { 0x55 })}|${b64(good.mac)}"
        refused("MAC mismatch") { VaultCrypto.decrypt(forged, f.userKey) }
        // A real ciphertext under another key: also the MAC.
        refused("MAC mismatch") { VaultCrypto.decrypt(f["encUserNotes"], f.orgKey) }
        // A correct MAC over a ciphertext whose padding is wrong is still refused, by the cipher.
        val key = SymmetricKey(ByteArray(64) { it.toByte() })
        val iv = ByteArray(16)
        val ct = ByteArray(16) { 0x33 }
        val mac = com.ritwick.sudostamp.Hpke.hmac(ByteArray(32) { (it + 32).toByte() }, iv + ct)
        refused("AES-CBC refused") { VaultCrypto.decrypt("2.${b64(iv)}|${b64(ct)}|${b64(mac)}", key) }
    }

    @Test
    fun `every single flipped bit in iv, ct or mac is refused`() {
        val good = EncString.parse(f["encItemName"]) as EncString.AesCbcHmac
        val ik = SymmetricKey(VaultCrypto.decrypt(f["encItemKey"], f.userKey))
        val all = good.iv + good.ct + good.mac
        for (bit in 0 until all.size * 8) {
            val b = all.copyOf().also { it[bit / 8] = (it[bit / 8].toInt() xor (1 shl (bit % 8))).toByte() }
            val iv = b.copyOfRange(0, 16)
            val ct = b.copyOfRange(16, 16 + good.ct.size)
            val mac = b.copyOfRange(16 + good.ct.size, b.size)
            refused("MAC mismatch") { VaultCrypto.decrypt("2.${b64(iv)}|${b64(ct)}|${b64(mac)}", ik) }
        }
        assertEquals(f["itemName"], VaultCrypto.decrypt(good, ik).toString(Charsets.UTF_8))
    }

    // ---- EncString: the parser

    @Test
    fun `EncString types other than 2 and 4 are refused, type 0 included`() {
        val g = EncString.parse(f["encItemName"]) as EncString.AesCbcHmac
        val parts3 = "${b64(g.iv)}|${b64(g.ct)}|${b64(g.mac)}"
        val parts2 = "${b64(g.iv)}|${b64(g.ct)}"
        val rsa = f["encOrgKey"].substring(2)
        for (t in listOf('0', '1', '3', '5', '6', '7', '8', '9', 'a', '-')) {
            for (body in listOf(parts3, parts2, rsa, "$rsa|${b64(g.mac)}")) {
                refused("EncString type $t refused") { EncString.parse("$t.$body") }
            }
        }
        // No type at all is Bitwarden's legacy type 0 (no MAC); two digits is no type we know.
        refused("EncString without a type") { EncString.parse(parts2) }
        refused("EncString without a type") { EncString.parse(parts3) }
        refused("EncString without a type") { EncString.parse("12.$parts3") }
        refused("EncString without a type") { EncString.parse(".$parts3") }
        refused("EncString without a type") { EncString.parse("") }
        refused("EncString without a type") { EncString.parse("2") }
        // Type 0 around a ciphertext that would open under the right key must still be refused.
        val ik = SymmetricKey(VaultCrypto.decrypt(f["encItemKey"], f.userKey))
        refused("EncString type 0 refused") { VaultCrypto.decrypt("0.$parts3", ik) }
    }

    @Test
    fun `type 2 with the wrong shape is refused`() {
        val g = EncString.parse(f["encItemName"]) as EncString.AesCbcHmac
        val iv = b64(g.iv); val ct = b64(g.ct); val mac = b64(g.mac)
        refused("type 2 needs 3 parts, got 2") { EncString.parse("2.$iv|$ct") }
        refused("type 2 needs 3 parts, got 4") { EncString.parse("2.$iv|$ct|$mac|$mac") }
        refused("type 2 needs 3 parts, got 1") { EncString.parse("2.") }
        refused("empty base64") { EncString.parse("2.$iv||$mac") }
        refused("iv of 15 bytes") { EncString.parse("2.${b64(ByteArray(15))}|$ct|$mac") }
        refused("iv of 17 bytes") { EncString.parse("2.${b64(ByteArray(17))}|$ct|$mac") }
        refused("mac of 31 bytes") { EncString.parse("2.$iv|$ct|${b64(ByteArray(31))}") }
        refused("ciphertext of 15 bytes") { EncString.parse("2.$iv|${b64(ByteArray(15))}|$mac") }
        refused("bad base64") { EncString.parse("2.$iv|$ct|${mac.replace('=', '*')}") }
        refused("bad base64") { EncString.parse("2.$iv |$ct|$mac") }
        refused("bad base64") { EncString.parse("2.${"-".repeat(22)}==|$ct|$mac") }
        refused("EncString too long") { EncString.parse("2." + "A".repeat(EncString.MAX_CHARS)) }
        refused("RSA ciphertext of 255 bytes") { EncString.parse("4." + b64(ByteArray(255))) }
        refused("type 4 has one part") { EncString.parse(f["encOrgKey"] + "|" + mac) }
    }

    @Test
    fun `non-canonical base64 is refused`() {
        val g = EncString.parse(f["encItemName"]) as EncString.AesCbcHmac
        val iv = b64(g.iv); val ct = b64(g.ct); val mac = b64(g.mac)
        // Unpadded: Java's decoder accepts it, the parser must not.
        refused("non-canonical base64") { EncString.parse("2.${iv.trimEnd('=')}|$ct|$mac") }
        // Non-zero trailing bits that decode to the same 16 bytes: two spellings of one iv.
        val last = iv[iv.length - 3]
        val alias = iv.substring(0, iv.length - 3) + (last + 1) + "=="
        assertArrayEquals(g.iv, Base64.getDecoder().decode(alias))
        refused("non-canonical base64") { EncString.parse("2.$alias|$ct|$mac") }
        // Round trip of what is accepted.
        assertEquals(f["encItemName"], EncString.parse(f["encItemName"]).encode())
        assertEquals(f["encOrgKey"], EncString.parse(f["encOrgKey"]).encode())
    }

    // ---- encryption, wiping

    @Test
    fun `encrypt round-trips with a fresh iv each time`() {
        val k = f.orgKey
        for (n in listOf(0, 1, 15, 16, 17, 1024)) {
            val pt = ByteArray(n) { (it * 31).toByte() }
            val a = VaultCrypto.encrypt(pt, k)
            val b = VaultCrypto.encrypt(pt, k)
            assertFalse(a.iv.contentEquals(b.iv))
            assertEquals((n / 16 + 1) * 16, a.ct.size)
            assertArrayEquals(pt, VaultCrypto.decrypt(a.encode(), k))
            assertArrayEquals(pt, VaultCrypto.decrypt(b, k))
        }
    }

    @Test
    fun `wipe zeroes the key material`() {
        val k = f.userKey
        assertTrue(k.copyBytes().any { it != 0.toByte() })
        k.wipe()
        assertTrue(k.copyBytes().all { it == 0.toByte() })
        refused("MAC mismatch") { VaultCrypto.decrypt(f["encUserNotes"], k) }
        val pk = f.privateKey
        pk.wipe()
        assertTrue(pk.bytes().all { it == 0.toByte() })
        val m = f.masterKey.copyOf()
        VaultCrypto.wipe(m)
        assertTrue(m.all { it == 0.toByte() })
    }

    /**
     * Kotlin-made output for an INDEPENDENT opener: tools/verify_vault_crypto.py recomputes the
     * derivations with pyca and opens these ciphertexts with its own type 2 code, plus a flipped-bit
     * negative control. Vectors prove we read pyca's; this proves pyca reads ours.
     */
    @Test
    fun `emit Kotlin-made vault crypto for external verification`() {
        val out = File("build/vaultcheck").apply { mkdirs() }
        File(out, "masterkey.bin").writeBytes(f.masterKey)
        File(out, "hash.txt").writeText(VaultCrypto.masterPasswordHash(f.masterKey, f.password))
        File(out, "stretched.bin").writeBytes(f.stretched.copyBytes())
        val pt = "made by VaultCrypto.kt \u00e9 \uD83D\uDD11".toByteArray(Charsets.UTF_8) + ByteArray(40).also { java.security.SecureRandom().nextBytes(it) }
        File(out, "org-text.bin").writeBytes(pt)
        File(out, "org-text.enc").writeText(VaultCrypto.encrypt(pt, f.orgKey).encode())
        File(out, "item-key-rewrapped.enc").writeText(VaultCrypto.rewrapItemKey(f["encItemKey"], f.userKey, f.orgKey).encode())
        File(out, "user-key.enc").writeText(VaultCrypto.encrypt(f.userKey.copyBytes(), f.stretched).encode())
        assertEquals(7, out.list()!!.size)
    }
}
