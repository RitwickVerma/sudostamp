package com.ritwick.sudostamp.vault

/**
 * Which vault items a grant may move into the Agents collection (docs/design/vault-grant.md 5).
 * Pure: [ItemView] is what the vault client (phase 2) reports about an item WITHOUT decrypting
 * anything it does not have to. Whether a TOTP seed, an attachment or a passkey is present is read
 * from the field's presence, never from its decrypted value.
 *
 * A refusal is for the owner's screen and the phone's own logs. The computer never learns which
 * one it was: every refusal is the same FAILURE on the wire (section 4).
 */
enum class ItemType { LOGIN, NOTE, CARD, IDENTITY, OTHER }

enum class ItemOwner { PERSONAL, ORG }

class ItemView(
    val type: ItemType,
    val hasTotp: Boolean,
    val hasAttachments: Boolean,
    val hasPasskeys: Boolean,
    /** Every saved URI, as the server holds it (decrypted on the phone). */
    val uris: List<String>,
    /** True when the item JSON has any field this client does not model. */
    val unknownFields: Boolean,
    val inAgentsCollection: Boolean,
    val owner: ItemOwner,
)

enum class GrantRefusal {
    /** The request host does not parse (GrantHost.parse). */
    BAD_HOST,

    /** The request host is on the denylist: refused before anything is shown. */
    DENYLISTED_HOST,

    /** The item has a field this client does not model: changing it could lose data. */
    UNKNOWN_FIELDS,

    /** Only Login items are granted; cards, identities and notes never are. */
    NOT_LOGIN,

    /** Re-encrypting attachments is out of scope: fail closed. */
    ATTACHMENTS,

    /** Passkeys likewise. */
    PASSKEYS,

    /** A TOTP seed, and the owner did not tick "allow" on this grant. */
    TOTP,

    /** No URI of the item matches the request host. */
    NO_MATCH,

    /** A URI the denylist cannot read (not http/https, an IP literal, garbage): it cannot be checked. */
    UNCHECKABLE_URI,

    /** A URI of the item is on the denylist, even if another URI matched the request. */
    DENYLISTED_URI,
}

object ItemRules {

    /** Why [host] is refused before the screen, or null when it may be shown to the owner. */
    fun hostRefusal(host: String, deny: Denylist): GrantRefusal? {
        val h = GrantHost.parse(host) ?: return GrantRefusal.BAD_HOST
        return if (deny.denies(h)) GrantRefusal.DENYLISTED_HOST else null
    }

    /** True when [item] is a candidate for [host]: a Login item with a URI that matches it. */
    fun matches(host: String, item: ItemView): Boolean =
        item.type == ItemType.LOGIN && item.uris.any { GrantHost.matchesUri(host, it) }

    /**
     * Why [item] may not be granted for [host], or null when it may. [allowTotp] is the owner's
     * tick on this one grant. Checked after the owner picks the item and before fingerprint 2;
     * the host is checked again here so this function alone is the whole rule.
     *
     * Every URI is checked against the denylist, not only the one that matched: an item saved for
     * both `shop.example.com` and a bank would otherwise move the bank login with it.
     */
    fun grantRefusal(host: String, item: ItemView, allowTotp: Boolean, deny: Denylist): GrantRefusal? {
        hostRefusal(host, deny)?.let { return it }
        if (item.unknownFields) return GrantRefusal.UNKNOWN_FIELDS
        if (item.type != ItemType.LOGIN) return GrantRefusal.NOT_LOGIN
        if (item.hasAttachments) return GrantRefusal.ATTACHMENTS
        if (item.hasPasskeys) return GrantRefusal.PASSKEYS
        if (item.hasTotp && !allowTotp) return GrantRefusal.TOTP
        if (!matches(host, item)) return GrantRefusal.NO_MATCH
        val hosts = item.uris.map { GrantHost.fromUri(it) }
        if (hosts.any { it == null }) return GrantRefusal.UNCHECKABLE_URI
        if (hosts.any { deny.denies(it!!) }) return GrantRefusal.DENYLISTED_URI
        return null
    }
}
