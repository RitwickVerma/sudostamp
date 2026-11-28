package com.ritwick.sudostamp.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Grant eligibility (docs/design/vault-grant.md 5): one rule per test, each one's own mutant. */
class ItemRulesTest {

    private val deny = Denylist.builtIn(DenylistTest.assetText())

    private fun item(
        type: ItemType = ItemType.LOGIN, totp: Boolean = false, attachments: Boolean = false, passkeys: Boolean = false,
        uris: List<String> = listOf("https://example.com/login"), unknown: Boolean = false,
        agents: Boolean = false, owner: ItemOwner = ItemOwner.PERSONAL,
    ) = ItemView(type, totp, attachments, passkeys, uris, unknown, agents, owner)

    private fun refusal(i: ItemView, host: String = "login.example.com", allowTotp: Boolean = false) =
        ItemRules.grantRefusal(host, i, allowTotp, deny)

    @Test
    fun plainLoginIsEligible() {
        assertNull(refusal(item()))
        assertNull(refusal(item(owner = ItemOwner.ORG)))
        assertNull(refusal(item(), host = "example.com"))
        assertNull(refusal(item(uris = listOf("example.com", "https://www.example.com/"))))
    }

    @Test
    fun hostRefusedBeforeTheScreen() {
        assertEquals(GrantRefusal.BAD_HOST, ItemRules.hostRefusal("Example.com", deny))
        assertEquals(GrantRefusal.DENYLISTED_HOST, ItemRules.hostRefusal("accounts.google.com", deny))
        assertNull(ItemRules.hostRefusal("example.com", deny))
        assertEquals(GrantRefusal.DENYLISTED_HOST, refusal(item(uris = listOf("https://paypal.com")), host = "paypal.com"))
    }

    @Test
    fun onlyLoginItems() {
        for (t in listOf(ItemType.NOTE, ItemType.CARD, ItemType.IDENTITY, ItemType.OTHER)) {
            assertEquals(GrantRefusal.NOT_LOGIN, refusal(item(type = t)))
            assertFalse(ItemRules.matches("login.example.com", item(type = t)))
        }
    }

    @Test
    fun attachmentsRefused() {
        assertEquals(GrantRefusal.ATTACHMENTS, refusal(item(attachments = true)))
        assertEquals(GrantRefusal.ATTACHMENTS, refusal(item(attachments = true), allowTotp = true))
    }

    @Test
    fun passkeysRefused() {
        assertEquals(GrantRefusal.PASSKEYS, refusal(item(passkeys = true)))
    }

    @Test
    fun totpRefusedUnlessAllowed() {
        assertEquals(GrantRefusal.TOTP, refusal(item(totp = true), allowTotp = false))
        assertNull(refusal(item(totp = true), allowTotp = true))
    }

    @Test
    fun unknownFieldsRefused() {
        assertEquals(GrantRefusal.UNKNOWN_FIELDS, refusal(item(unknown = true)))
    }

    @Test
    fun mustMatchTheHost() {
        assertEquals(GrantRefusal.NO_MATCH, refusal(item(), host = "evilexample.com"))
        assertEquals(GrantRefusal.NO_MATCH, refusal(item(uris = listOf("https://amazon.co.uk")), host = "co.uk"))
        assertEquals(GrantRefusal.NO_MATCH, refusal(item(uris = emptyList())))
        assertTrue(ItemRules.matches("login.example.com", item()))
    }

    @Test
    fun everyUriCheckedAgainstTheDenylist() {
        // Matched on example.com, but the same item also opens a bank: refused.
        assertEquals(GrantRefusal.DENYLISTED_URI,
            refusal(item(uris = listOf("https://example.com", "https://secure.chase.com/"))))
        assertEquals(GrantRefusal.DENYLISTED_URI,
            refusal(item(uris = listOf("https://example.com", "https://www.gmail.com"))))
    }

    @Test
    fun uncheckableUriRefused() {
        assertEquals(GrantRefusal.UNCHECKABLE_URI,
            refusal(item(uris = listOf("https://example.com", "androidapp://com.example.bank"))))
        assertEquals(GrantRefusal.UNCHECKABLE_URI,
            refusal(item(uris = listOf("https://example.com", "https://192.0.2.10/"))))
    }

    @Test
    fun ownerAndServerLayersApplyToItems() {
        val withServer = deny.withServer("https://pw.example.net")!!
        assertEquals(GrantRefusal.DENYLISTED_URI,
            ItemRules.grantRefusal("example.com", item(uris = listOf("https://example.com", "https://pw.example.net")), false, withServer))
        val withOwner = deny.withOwnerHost("example.org")!!
        assertEquals(GrantRefusal.DENYLISTED_URI,
            ItemRules.grantRefusal("example.com", item(uris = listOf("example.com", "shop.example.org")), false, withOwner))
    }
}
