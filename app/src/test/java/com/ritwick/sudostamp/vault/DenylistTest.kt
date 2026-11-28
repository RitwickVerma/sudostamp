package com.ritwick.sudostamp.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/**
 * The denylist: the shipped asset parses, gives every answer in the shared vectors file
 * (test resources `vault/denylist-vectors.txt`, which the login service imports too), and the
 * owner and server layers behave.
 */
class DenylistTest {

    companion object {
        /** The asset as it ships. The test JVM runs in the module directory (app/). */
        fun assetText(): String {
            val f = listOf("src/main/assets", "app/src/main/assets").map { File(it, Denylist.ASSET) }.first { it.isFile }
            return f.readText(Charsets.UTF_8)
        }

        fun vectors(): List<Pair<Boolean, String>> {
            val text = DenylistTest::class.java.getResource("/vault/denylist-vectors.txt")!!.readText(Charsets.UTF_8)
            return text.split('\n').filter { it.isNotEmpty() && !it.startsWith("#") }.map { line ->
                val (verdict, host) = line.split(' ').also { require(it.size == 2) { "bad vector line <$line>" } }
                require(verdict == "allow" || verdict == "deny") { "bad verdict <$line>" }
                (verdict == "deny") to host
            }
        }
    }

    private val list = Denylist.builtIn(assetText())

    @Test
    fun assetParsesWithEveryCategory() {
        val rules = list.rules.map { it.toString() }.toSet()
        for (r in listOf("host:gmail.com", "host:google.com", "host:outlook.com", "host:live.com", "host:microsoft.com",
            "host:icloud.com", "host:apple.com", "host:yahoo.com", "host:proton.me", "host:protonmail.com",
            "host:okta.com", "host:auth0.com", "host:login.gov", "host:paypal.com", "host:stripe.com",
            "host:venmo.com", "host:wise.com", "host:robinhood.com", "host:fidelity.com", "host:schwab.com",
            "host:vanguard.com", "host:coinbase.com", "host:bitwarden.com", "host:bitwarden.eu",
            "host:1password.com", "host:lastpass.com", "host:dashlane.com", "host:keepersecurity.com",
            "suffix:gov", "suffix:mil", "suffix:gov.in", "suffix:gov.uk", "suffix:nic.in",
            "contains:bank", "contains:vault", "contains:immigration", "contains:uscis", "contains:tax", "label:irs")) {
            assertTrue("asset lacks $r", r in rules)
        }
    }

    @Test
    fun sharedVectors() {
        val v = vectors()
        assertTrue("too few vectors: ${v.size}", v.size >= 60)
        assertTrue(v.any { it.first } && v.any { !it.first })
        for ((deny, host) in v) {
            assertNotNull("vector <$host> is not a request host", GrantHost.parse(host))
            assertEquals("$host should be ${if (deny) "denied" else "allowed"}", deny, list.denies(host))
            assertEquals(!deny, list.allows(host))
        }
    }

    @Test
    fun invalidHostsAreDenied() {
        for (h in listOf("", "Gmail.com", "example.com.", "1.2.3.4", "com", "ex\u00e4mple.com")) assertTrue(h, list.denies(h))
    }

    @Test
    fun ownerHostsAddAndRemoveButBuiltInsStay() {
        assertTrue(list.allows("shop.example.com"))
        val more = list.withOwnerHost("example.com")!!
        assertTrue(more.denies("shop.example.com"))
        assertTrue(more.denies("example.com"))
        assertFalse(more.denies("evilexample.com"))
        assertTrue(more.withoutOwnerHost("example.com").allows("shop.example.com"))
        // Removing a built-in host is a no-op: it was never the owner's to remove.
        val tried = list.withOwnerHost("gmail.com")!!.withoutOwnerHost("gmail.com")
        assertTrue(tried.denies("gmail.com"))
        assertNull(list.withOwnerHost("Example.COM"))
        assertNull(list.withOwnerHost("not a host"))
    }

    @Test
    fun serverHostIsDenied() {
        assertTrue(list.allows("pw.example.net"))
        val s = list.withServer("https://pw.example.net:8443/")!!
        assertEquals("pw.example.net", s.serverHost)
        assertTrue(s.denies("pw.example.net"))
        assertTrue(s.denies("admin.pw.example.net"))
        assertFalse(s.denies("example.net"))
        assertTrue(s.withOwnerHost("shop.example.com")!!.denies("pw.example.net"))
        assertTrue(s.withoutOwnerHost("pw.example.net").denies("pw.example.net"))
        assertNull(list.withServer("https://192.0.2.10:8443"))
    }

    @Test
    fun labelRulesAreExactOrContaining() {
        assertTrue(list.denies("irs.example.org"))
        assertFalse(list.denies("first.example.org"))      // label: exact
        assertTrue(list.denies("mybank.example"))           // contains:
        assertTrue(list.denies("bank.example"))
        assertTrue(list.denies("a.b.vaultwarden.example"))
    }

    @Test
    fun parserIsStrict() {
        val good = Denylist.parseRules("# c\n\nhost:example.com\nsuffix:gov\nlabel:irs\ncontains:bank\n")
        assertEquals(listOf("host:example.com", "suffix:gov", "label:irs", "contains:bank"), good.map { it.toString() })
        for (bad in listOf(
            "", "# only a comment\n", "host:example.com\r\n", "host:com", "host:Example.com", " host:example.com",
            "host:example.com ", "host:example.com # x", "hosts:example.com", "HOST:example.com", ":example.com",
            "example.com", "suffix:", "suffix:.gov", "suffix:gov.", "label:a.b", "label:-x", "contains:", "contains:Bank",
            "host:example.com\nhost:example.com", "label:x\u00e4", "suffix:123", "host:1.2.3.4",
        )) {
            try {
                Denylist.parseRules(bad)
                fail("accepted <$bad>")
            } catch (e: IllegalArgumentException) {
                // the refusal
            }
        }
    }

    @Test
    fun parseErrorNamesTheLine() {
        val e = try {
            Denylist.parseRules("host:example.com\n# ok\nnope:x\n")
            null
        } catch (e: IllegalArgumentException) {
            e
        }
        assertTrue(e!!.message!!.contains("line 3"))
    }
}
