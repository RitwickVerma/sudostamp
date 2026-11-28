package com.ritwick.sudostamp.vault

/**
 * The host a grant names, and the hosts saved in vault items (docs/design/vault-grant.md 4 and 5).
 * Pure: no Android, so the JVM tests own it.
 *
 * WHY SO STRICT: the request host is the only thing a computer chooses in a grant. It is shown on
 * the phone's screen, matched against item URIs and checked against the denylist, so it must have
 * exactly one spelling. Uppercase, a trailing dot, an IP literal or a Unicode look-alike would each
 * be a second spelling of some host the denylist names, so they are refused rather than normalised:
 * the computer can send the canonical form, and anything else is a bug or an attack.
 */
object GrantHost {

    const val MAX_BYTES = 253
    const val MAX_LABEL = 63

    /**
     * [raw] as a request host, or null for anything that is not exactly one: 1..253 bytes of
     * ASCII, lowercase LDH labels of 1..63 bytes with no leading or trailing hyphen, no empty
     * label, no trailing dot, at least two labels. A-labels (`xn--...`) pass as plain LDH.
     *
     * The last label may not be all digits. No TLD is (RFC 3696 2), so this refuses IPv4 literals,
     * where suffix matching means nothing (`2.3.4` is not a parent of `1.2.3.4`).
     */
    fun parse(raw: ByteArray): String? {
        if (raw.isEmpty() || raw.size > MAX_BYTES) return null
        for (b in raw) if (!ldh(b.toInt() and 0xFF) && b != DOT) return null
        return parseLabels(String(raw, Charsets.US_ASCII), minLabels = 2)
    }

    /** [s] as a request host, by the rules of [parse]. Never throws. */
    fun parse(s: String): String? {
        if (s.isEmpty() || s.length > MAX_BYTES || s.any { it.code > 0x7F }) return null
        return parse(s.toByteArray(Charsets.US_ASCII))
    }

    /**
     * [s] if it is a dot-separated run of at least [minLabels] valid labels (the checks of
     * [parse]; ASCII and length are the caller's), else null. Also used for denylist suffixes,
     * which may be one label (`gov`).
     */
    internal fun parseLabels(s: String, minLabels: Int): String? {
        if (s.isEmpty() || s.length > MAX_BYTES) return null
        val labels = s.split('.')
        if (labels.size < minLabels) return null
        if (!labels.all { validLabel(it) }) return null
        if (labels.last().all { it in '0'..'9' }) return null
        return s
    }

    /** One LDH label: 1..63 of [a-z0-9-], not starting or ending with a hyphen. */
    internal fun validLabel(l: String): Boolean =
        l.length in 1..MAX_LABEL && l.all { ldh(it.code) } && l.first() != '-' && l.last() != '-'

    private const val DOT = '.'.code.toByte()

    private fun ldh(c: Int): Boolean = c in 'a'.code..'z'.code || c in '0'.code..'9'.code || c == '-'.code

    /**
     * The host of a URI saved in a vault item, ready for [matches], or null when it has none this
     * client can trust: a scheme other than http or https (`androidapp://`, `ftp://`), an IPv6
     * literal, a port that is not digits, a host that [parse] refuses after lowercasing. A URI
     * without `://` is read as a bare host (Bitwarden saves what the owner typed). Userinfo and the
     * port are dropped, the host is lowercased (ASCII only: a non-ASCII host is refused, never
     * case-folded by a locale) and ONE leading `www.` is stripped.
     *
     * Null means "no match" for matching, and "cannot be checked" for the denylist: the item rules
     * refuse an item with such a URI (ItemRules), so an unparseable URI never slips past either.
     */
    fun fromUri(uri: String): String? {
        if (uri.isEmpty() || uri.length > 4096 || uri.any { it.code <= 0x20 || it.code > 0x7E }) return null
        val sep = uri.indexOf("://")
        val rest = if (sep >= 0) {
            val scheme = uri.substring(0, sep).lowercase(java.util.Locale.ROOT)
            if (scheme != "http" && scheme != "https") return null
            uri.substring(sep + 3)
        } else {
            uri
        }
        val end = rest.indexOfFirst { it == '/' || it == '?' || it == '#' || it == '\\' }
        var authority = if (end >= 0) rest.substring(0, end) else rest
        // Userinfo only after a scheme: a bare `mailto:a@example.com` is not a saved host.
        if (sep < 0 && authority.contains('@')) return null
        authority = authority.substring(authority.lastIndexOf('@') + 1)
        if (authority.startsWith("[")) return null
        val colon = authority.indexOf(':')
        if (colon >= 0) {
            val port = authority.substring(colon + 1)
            if (port.isEmpty() || port.length > 5 || !port.all { it in '0'..'9' }) return null
            authority = authority.substring(0, colon)
        }
        var host = authority.lowercase(java.util.Locale.ROOT)
        if (host.startsWith("www.")) host = host.substring(4)
        return parse(host)
    }

    /**
     * Section 5: saved host [u] matches request host [h] when they are equal or [h] is a subdomain
     * of [u]. The dot matters: without it `evilexample.com` would match `example.com`. No public
     * suffix list: a request for `co.uk` is not a subdomain of `amazon.co.uk`, so it matches
     * nothing saved there. Both must already be parsed hosts.
     */
    fun matches(h: String, u: String): Boolean = h == u || h.endsWith(".$u")

    /** [matches] against a saved URI: false when [fromUri] cannot read it. */
    fun matchesUri(h: String, uri: String): Boolean = fromUri(uri)?.let { matches(h, it) } ?: false
}
