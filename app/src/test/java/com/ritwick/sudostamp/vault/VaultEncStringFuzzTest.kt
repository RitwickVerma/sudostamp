package com.ritwick.sudostamp.vault

import com.ritwick.sudostamp.Fuzz
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64
import java.util.Random

/**
 * EncStrings come from the server's sync: hostile input. Properties, seeded (FuzzSupport.kt):
 *  1. the parser accepts exactly what an independent reference accepts, and nothing it is fed
 *     -- random text, damaged real EncStrings -- ever throws anything but [VaultRefused], through
 *     the parser or any of the decrypt paths;
 *  2. one flipped bit anywhere in iv, ct or mac of a real type 2 is refused by the MAC;
 *  3. authentic ciphertexts whose content is not a key (random bytes and lengths) are refused as
 *     keys, never thrown out of the provider.
 */
class VaultEncStringFuzzTest {
    private val f = VaultVectors
    private val userKey = f.userKey
    private val privateKey = f.privateKey

    private val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    /**
     * Written from the format, not from EncString.parse: a type digit and a dot, then for type 2
     * three canonical base64 fields (iv 16 bytes, mac 32, ct a non-zero multiple of 16), for type
     * 4 one canonical base64 field of 256 bytes. Base64 is checked character by character here,
     * never with java.util.Base64.
     */
    private fun reference(s: String): Boolean {
        if (s.length > EncString.MAX_CHARS || s.length < 2 || s[1] != '.') return false
        val body = s.substring(2)
        return when (s[0]) {
            '2' -> body.split('|').let { p -> p.size == 3 && b64Len(p[0]) == 16 && b64Len(p[2]) == 32 && b64Len(p[1]).let { it > 0 && it % 16 == 0 } }
            '4' -> '|' !in body && b64Len(body) == 256
            else -> false
        }
    }

    /** Decoded length of canonical padded base64, or -1. */
    private fun b64Len(s: String): Int {
        if (s.isEmpty() || s.length % 4 != 0) return -1
        val pad = s.takeLastWhile { it == '=' }.length
        if (pad > 2) return -1
        val data = s.dropLast(pad)
        if (data.any { it !in alphabet }) return -1
        // The bits after the last whole byte must be zero, or two texts mean one value.
        val last = alphabet.indexOf(data.last())
        if (pad == 2 && last and 0xF != 0) return -1
        if (pad == 1 && last and 0x3 != 0) return -1
        return s.length / 4 * 3 - pad
    }

    private fun b64(b: ByteArray) = Base64.getEncoder().encodeToString(b)

    private val seeds: List<String> = listOf(
        "encItemName", "encItemKey", "encUserKey", "encPrivateKey", "encOrgKey", "encOrgText", "encEmpty", "encOrgKeyShort",
    ).map { f[it] }

    private fun damaged(r: Random, s: String): String {
        val c = StringBuilder(s)
        when (r.nextInt(9)) {
            0 -> c.setLength(r.nextInt(s.length + 1))
            1 -> repeat(1 + r.nextInt(3)) { if (c.isNotEmpty()) c.setCharAt(r.nextInt(c.length), "0123456789.|=+/Aa \u00e9"[r.nextInt(17)]) }
            2 -> c.insert(r.nextInt(c.length + 1), "|.=A0"[r.nextInt(5)])
            3 -> if (c.isNotEmpty()) c.deleteCharAt(r.nextInt(c.length))
            4 -> c.setCharAt(0, "0123456789x"[r.nextInt(11)])
            5 -> c.append("|" + b64(Fuzz.bytes(r, r.nextInt(40))))
            6 -> return s.split('|').shuffled(r).joinToString("|")
            7 -> return s.replace("=", "")
            else -> return s.substring(0, 2) + s.substring(2).split('|').joinToString("|") { if (r.nextBoolean()) it else b64(Fuzz.bytes(r, r.nextInt(48))) }
        }
        return c.toString()
    }

    private fun candidate(r: Random): String = when (r.nextInt(4)) {
        0 -> String(CharArray(r.nextInt(80)) { "0123456789.|=+/ABab"[r.nextInt(19)] })
        1 -> "${"0123456789"[r.nextInt(10)]}." + (0 until 1 + r.nextInt(4)).joinToString("|") { b64(Fuzz.bytes(r, intArrayOf(0, 15, 16, 17, 31, 32, 33, 48, 255, 256, 257)[r.nextInt(11)])) }
        else -> damaged(r, seeds[r.nextInt(seeds.size)])
    }

    /** Runs [block]; true if it returned, false if it was refused. Anything else propagates. */
    private inline fun accepted(block: () -> Unit): Boolean = try {
        block(); true
    } catch (e: VaultRefused) {
        false
    }

    @Test
    fun `parser agrees with an independent reference and only ever refuses`() {
        var parsed = 0
        Fuzz.run("vault-encstring-parse", 0x7A01, weight = 100) { _, r ->
            val s = candidate(r)
            var e: EncString? = null
            val ok = accepted { e = EncString.parse(s) }
            assertEquals("parse of <$s>", reference(s), ok)
            val enc = e ?: return@run
            parsed++
            assertEquals(s, enc.encode())
            // Every decrypt path: refused or opened, never a provider exception.
            accepted { VaultCrypto.decrypt(enc, userKey) }
            accepted { VaultCrypto.decryptUserKey(s, userKey) }
            accepted { VaultCrypto.decryptPrivateKey(s, userKey) }
            accepted { VaultCrypto.rewrapItemKey(s, userKey, userKey) }
            if (enc is EncString.RsaOaepSha1) accepted { VaultCrypto.unwrapOrgKey(s, privateKey) }
        }
        println("vault-encstring-parse: $parsed candidates parsed and sent through every decrypt path")
        assertTrue("too few candidates parsed ($parsed): the generator stopped reaching the decrypt paths", parsed > Fuzz.iterations / 50)
    }

    @Test
    fun `one flipped bit in iv, ct or mac is refused`() {
        Fuzz.run("vault-encstring-bitflip", 0x7A02, weight = 100) { _, r ->
            val key = SymmetricKey(Fuzz.bytes(r, 64))
            val pt = Fuzz.bytes(r, r.nextInt(100))
            val e = VaultCrypto.encrypt(pt, key)
            val all = e.iv + e.ct + e.mac
            val bit = r.nextInt(all.size * 8)
            all[bit / 8] = (all[bit / 8].toInt() xor (1 shl (bit % 8))).toByte()
            val iv = all.copyOfRange(0, 16)
            val ct = all.copyOfRange(16, 16 + e.ct.size)
            val mac = all.copyOfRange(16 + e.ct.size, all.size)
            try {
                VaultCrypto.decrypt("2.${b64(iv)}|${b64(ct)}|${b64(mac)}", key)
                throw AssertionError("bit $bit flipped and it still opened")
            } catch (x: VaultRefused) {
                assertEquals("MAC mismatch", x.reason)
            }
            assertArrayEquals(pt, VaultCrypto.decrypt(e, key))
        }
    }

    @Test
    fun `authentic ciphertexts that are not keys are refused as keys`() {
        Fuzz.run("vault-not-a-key", 0x7A03, weight = 20) { _, r ->
            val n = if (r.nextInt(4) == 0) 64 else r.nextInt(1300)
            val junk = Fuzz.bytes(r, n)
            // Sometimes a DER-ish start, so the key parser gets past its first byte.
            if (n > 4 && r.nextBoolean()) { junk[0] = 0x30; junk[1] = 0x82.toByte() }
            val s = VaultCrypto.encrypt(junk, userKey).encode()
            assertEquals(n == 64, accepted { VaultCrypto.decryptUserKey(s, userKey).wipe() })
            assertEquals(n == 64, accepted { VaultCrypto.rewrapItemKey(s, userKey, userKey) })
            assertFalse(accepted { VaultCrypto.decryptPrivateKey(s, userKey) })
        }
    }
}
