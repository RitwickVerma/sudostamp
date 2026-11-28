package com.ritwick.sudostamp.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The request-host parser, URI-host extraction and matching (docs/design/vault-grant.md 4, 5). */
class GrantHostTest {

    @Test
    fun acceptsCanonicalHosts() {
        for (h in listOf("example.com", "login.example.com", "a.b", "xn--mnchen-3ya.de", "a-b.c-d.example",
            "1password.com", "co.uk", "x.y.z.w.example", "a1.b2")) {
            assertEquals(h, GrantHost.parse(h))
            assertEquals(h, GrantHost.parse(h.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun refusesEverythingElse() {
        for (h in listOf("", "com", "Example.com", "EXAMPLE.COM", "example.com.", ".example.com", "example..com",
            "-a.com", "a-.com", "a.-com", "a.com-", "a_b.com", "a b.com", "exa\u0000mple.com", "ex\u00e4mple.com",
            "\u0435xample.com", "example.com:443", "user@example.com", "1.2.3.4", "example.123", "*.example.com",
            "example.com/", "example.com\n", " example.com", "[::1]", "a..", ".")) {
            assertNull("accepted <$h>", GrantHost.parse(h))
        }
    }

    @Test
    fun lengthLimits() {
        val l63 = "a".repeat(63)
        assertEquals("$l63.com", GrantHost.parse("$l63.com"))
        assertNull(GrantHost.parse("a$l63.com"))
        // 253 bytes exactly: four 62-byte labels and dots = 251, plus ".a" would be 253.
        val h253 = List(4) { "b".repeat(62) }.joinToString(".") + ".a"
        assertEquals(253, h253.length)
        assertEquals(h253, GrantHost.parse(h253))
        assertNull(GrantHost.parse("c$h253"))
        assertNull(GrantHost.parse(ByteArray(254) { 'a'.code.toByte() }))
    }

    @Test
    fun rawBytesMustBeAscii() {
        assertNull(GrantHost.parse(byteArrayOf(0xC3.toByte(), 0xA4.toByte(), '.'.code.toByte(), 'd'.code.toByte(), 'e'.code.toByte())))
        assertNull(GrantHost.parse(byteArrayOf('a'.code.toByte(), 0x80.toByte(), '.'.code.toByte(), 'b'.code.toByte())))
    }

    @Test
    fun uriHostExtraction() {
        val cases = mapOf(
            "https://example.com" to "example.com",
            "https://example.com/login?next=/" to "example.com",
            "http://Login.Example.COM:8080/x" to "login.example.com",
            "HTTPS://www.example.com" to "example.com",
            "https://www.www.example.com" to "www.example.com",
            "https://user:pw@shop.example.com/" to "shop.example.com",
            "https://a@b@shop.example.com" to "shop.example.com",
            "example.com" to "example.com",
            "www.example.com/path" to "example.com",
            "example.com:8443" to "example.com",
            "https://example.com#frag" to "example.com",
            "https://example.com?q" to "example.com",
            "https://example.com\\@evil.example" to "example.com",
        )
        for ((uri, host) in cases) assertEquals(uri, host, GrantHost.fromUri(uri))
    }

    @Test
    fun uriHostExtractionRefuses() {
        for (uri in listOf("", "androidapp://com.example.app", "ftp://example.com", "iosapp://x", "https://",
            "https://[2001:db8::1]/", "https://192.0.2.10/", "192.0.2.10", "https://example.com:http/",
            "https://example.com:/", "https://example.com:123456/", "https://ex ample.com", " https://example.com",
            "https://ex\u00e4mple.com", "https://example.com./", "https://localhost/", "https://www.com",
            "https://%65xample.com", "javascript:alert(1)", "mailto:a@example.com", "https://exa_mple.com",
            "https://example.com\t", "data:text/html,x")) {
            assertNull("read a host from <$uri>", GrantHost.fromUri(uri))
        }
    }

    @Test
    fun matchingSection5Vectors() {
        // The design's own vectors.
        assertFalse(GrantHost.matchesUri("co.uk", "https://amazon.co.uk/"))
        assertFalse(GrantHost.matchesUri("co.uk", "https://www.amazon.co.uk/"))
        assertTrue(GrantHost.matchesUri("login.example.com", "https://example.com"))
        assertFalse(GrantHost.matchesUri("evilexample.com", "https://example.com"))
        assertFalse(GrantHost.matches("evilexample.com", "example.com"))
    }

    @Test
    fun matchingRules() {
        assertTrue(GrantHost.matches("example.com", "example.com"))
        assertTrue(GrantHost.matches("a.b.example.com", "example.com"))
        assertFalse(GrantHost.matches("example.com", "login.example.com"))   // a parent is not matched by a child
        assertFalse(GrantHost.matches("example.com.evil.example", "example.com"))
        assertFalse(GrantHost.matches("xexample.com", "example.com"))
        assertTrue(GrantHost.matchesUri("example.com", "https://www.example.com/"))  // www. stripped from u
        assertFalse(GrantHost.matchesUri("example.com", "androidapp://example.com"))
        assertFalse(GrantHost.matchesUri("example.com", "not a uri"))
    }
}
