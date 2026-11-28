package com.ritwick.sudostamp.vault

import com.ritwick.sudostamp.AgentProtocol
import com.ritwick.sudostamp.Fuzz
import com.ritwick.sudostamp.Fuzz.str
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

/**
 * Properties of the vault-grant rules over seeded random input (FuzzSupport), each against a
 * reference written from the design (docs/design/vault-grant.md 4, 5), not from the code:
 *
 *  - GrantHost.parse agrees with one regular expression of the section 4 rules;
 *  - GrantHost.fromUri never throws, and anything it returns is a valid request host;
 *  - GrantHost.matches agrees with a label-list comparison (u's labels are a suffix of h's);
 *  - Denylist.parseRules never throws anything but its refusal (IllegalArgumentException);
 *  - GrantProtocol.parseRequest never throws, and accepts exactly two SSH strings, a valid host
 *    and a DER-looking signature of at most 72 bytes, with nothing after.
 */
class VaultRulesFuzzTest {

    /**
     * The reference host rule: 1..253 characters, labels of 1..63 lowercase LDH with no hyphen at
     * either end, at least two labels, and a last label that is not all digits.
     */
    private val ref = Regex(
        "(?=.{1,253}\$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?![0-9]+\$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    )

    private fun refHost(b: ByteArray): Boolean {
        if (b.any { it < 0 }) return false                              // not ASCII
        return ref.matches(String(b, Charsets.ISO_8859_1))
    }

    private val ALPHABET = "abcxyz019-.-.AZ_ \u0000\n\u00e4/:@"

    private fun label(r: Random): String = when (r.nextInt(8)) {
        0 -> ""
        1 -> "a".repeat(60 + r.nextInt(6))
        2 -> "xn--" + String(CharArray(1 + r.nextInt(8)) { "abc019"[r.nextInt(6)] })
        3 -> (0..r.nextInt(3)).joinToString("") { "${r.nextInt(10)}" }
        4 -> "-" + "ab"
        5 -> "ab-"
        else -> String(CharArray(1 + r.nextInt(10)) { "abcdefxyz0189-"[r.nextInt(14)] })
    }

    /** Host-shaped strings: mostly label runs (so acceptance is exercised), some noise. */
    private fun hostish(r: Random): String = when (r.nextInt(5)) {
        0 -> String(CharArray(r.nextInt(20)) { ALPHABET[r.nextInt(ALPHABET.length)] })
        1 -> List(1 + r.nextInt(6)) { label(r) }.joinToString(".") + if (r.nextInt(8) == 0) "." else ""
        2 -> List(3 + r.nextInt(3)) { "b".repeat(50 + r.nextInt(14)) }.joinToString(".")  // near 253
        else -> List(2 + r.nextInt(3)) { label(r) }.joinToString(".")
    }

    /** Both answers must occur, or a property passes by never reaching one side. */
    private fun bothSides(name: String, yes: Int, no: Int) =
        assertTrue("$name: accepted $yes, refused $no", yes > 0 && no > 0)

    @Test
    fun hostParserAgreesWithReference() {
        var yes = 0
        var no = 0
        Fuzz.run("GrantHost.parse", salt = 0x6701L) { i, r ->
        val raw = if (r.nextInt(6) == 0) Fuzz.bytes(r, r.nextInt(40)) else hostish(r).toByteArray(Charsets.UTF_8)
        val got = GrantHost.parse(raw)
        assertEquals("case $i <${String(raw, Charsets.ISO_8859_1)}>", refHost(raw), got != null)
        if (got != null) assertEquals(String(raw, Charsets.US_ASCII), got)
        assertEquals(got, GrantHost.parse(String(raw, Charsets.ISO_8859_1)))
        if (got != null) yes++ else no++
        }
        bothSides("GrantHost.parse", yes, no)
    }

    @Test
    fun uriExtractionNeverThrowsAndYieldsValidHosts() = Fuzz.run("GrantHost.fromUri", salt = 0x6702L) { _, r ->
        val scheme = listOf("https://", "http://", "HTTP://", "ftp://", "androidapp://", "", "", "://", "https:/")[r.nextInt(9)]
        val user = if (r.nextInt(5) == 0) "u:p@" else ""
        val www = if (r.nextInt(3) == 0) "www." else ""
        val port = listOf("", "", ":443", ":", ":x", ":99999")[r.nextInt(6)]
        val tail = listOf("", "/", "/a?b#c", "?q", "#f", "\\x")[r.nextInt(6)]
        val uri = if (r.nextInt(5) == 0) String(CharArray(r.nextInt(30)) { (r.nextInt(128)).toChar() })
        else scheme + user + www + hostish(r).uppercaseIf(r.nextInt(4) == 0) + port + tail
        val h = GrantHost.fromUri(uri)
        if (h != null) {
            assertEquals("fromUri <$uri> gave <$h>", h, GrantHost.parse(h))
            assertTrue(!h.startsWith("www.") || uri.lowercase().contains("www.www."))
        }
    }

    private fun String.uppercaseIf(b: Boolean) = if (b) uppercase() else this

    @Test
    fun matchingAgreesWithLabelReference() {
        var yes = 0
        var no = 0
        Fuzz.run("GrantHost.matches", salt = 0x6703L) { _, r ->
        val pool = listOf("example.com", "evilexample.com", "login.example.com", "a.login.example.com", "co.uk",
            "amazon.co.uk", "www.amazon.co.uk", "xample.com", "example.co", "com.example", "e.com")
        val h = if (r.nextBoolean()) pool[r.nextInt(pool.size)] else hostish(r)
        val u = if (r.nextBoolean()) pool[r.nextInt(pool.size)] else hostish(r)
        val hp = GrantHost.parse(h) ?: return@run
        val up = GrantHost.parse(u) ?: return@run
        val hl = hp.split('.')
        val ul = up.split('.')
        val refMatch = ul.size <= hl.size && hl.subList(hl.size - ul.size, hl.size) == ul
        assertEquals("<$hp> vs <$up>", refMatch, GrantHost.matches(hp, up))
        if (refMatch) yes++ else no++
        }
        bothSides("GrantHost.matches", yes, no)
    }

    @Test
    fun denylistParserOnlyRefuses() = Fuzz.run("Denylist.parseRules", salt = 0x6704L, weight = 25) { _, r ->
        val kinds = listOf("host:", "suffix:", "label:", "contains:", "nope:", "", "#", "HOST:")
        val text = List(r.nextInt(6)) {
            kinds[r.nextInt(kinds.size)] + if (r.nextInt(4) == 0) String(CharArray(r.nextInt(12)) { ALPHABET[r.nextInt(ALPHABET.length)] }) else hostish(r)
        }.joinToString(if (r.nextInt(10) == 0) "\r\n" else "\n")
        try {
            val rules = Denylist.parseRules(text)
            assertTrue(rules.isNotEmpty())
            val d = Denylist.builtIn(text)
            d.denies(hostish(r))
        } catch (e: IllegalArgumentException) {
            // the refusal
        }
    }

    private val sig = byteArrayOf(0x30) + ByteArray(70) { 1 }

    @Test
    fun grantRequestParserAgreesWithReference() {
        var yes = 0
        var no = 0
        Fuzz.run("GrantProtocol.parseRequest", salt = 0x6705L) { i, r ->
        val fields = ArrayList<ByteArray>()
        repeat(when (r.nextInt(8)) { 0 -> 0; 1 -> 1; 2 -> 3; else -> 2 }) { j ->
            fields += when (r.nextInt(5)) {
                0 -> Fuzz.bytes(r, r.nextInt(80))
                1 -> if (j == 0) sig else hostish(r).toByteArray(Charsets.UTF_8)
                2 -> if (j == 0) hostish(r).toByteArray(Charsets.UTF_8) else byteArrayOf(0x30) + Fuzz.bytes(r, 68 + r.nextInt(8))
                else -> if (j == 0) hostish(r).toByteArray(Charsets.UTF_8) else sig
            }
        }
        var body = fields.fold(ByteArray(0)) { acc, f -> acc + str(f) }
        val trailing = r.nextInt(8) == 0
        if (trailing) body += Fuzz.bytes(r, 1 + r.nextInt(4))
        var lied = false
        if (r.nextInt(10) == 0 && body.size >= 4) {
            // A hostile length in the first field.
            val l = Fuzz.LIES[r.nextInt(Fuzz.LIES.size)]
            if (l != Fuzz.readU32(body, 0)) { body = Fuzz.u32(l) + body.copyOfRange(4, body.size); lied = true }
        }
        val got = GrantProtocol.parseRequest(AgentProtocol.Reader(byteArrayOf(27) + body).also { it.skipType() })
        if (lied) return@run                                             // only "never throws" is checked
        val expect = fields.size == 2 && !trailing && refHost(fields[0]) &&
            fields[1].isNotEmpty() && fields[1].size <= 72 && fields[1][0] == 0x30.toByte()
        assertEquals("case $i", expect, got != null)
        if (got != null) assertEquals(String(fields[0], Charsets.US_ASCII), got.host)
        if (got != null) yes++ else no++
        }
        bothSides("GrantProtocol.parseRequest", yes, no)
    }
}
