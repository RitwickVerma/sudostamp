package com.ritwick.sudostamp.vault

/**
 * Hosts no grant may ever touch (docs/design/vault-grant.md 5): checked against the request host
 * before anything is shown, and against every URI of the chosen item before the fingerprint.
 *
 * Three layers, in one immutable value:
 *  - the BUILT-IN rules, from `assets/vault-denylist-v1.txt`. They cannot be removed: an owner who
 *    taps through a lookalike screen must still be unable to hand an agent a bank or a mailbox.
 *  - hosts the OWNER added on the phone. Removable; removing one never removes a built-in rule.
 *  - the vault SERVER's own host, added at setup: an agent must never be granted the login that
 *    opens the whole vault.
 *
 * Rule syntax, one rule per line, `kind:value`, nothing else on the line (no leading or trailing
 * space, no inline comment). A line starting with `#` is a comment; an empty line is skipped.
 *
 *     host:gmail.com     the host and every subdomain of it (the matching rule of section 5)
 *     suffix:gov         the same, but the value may be a single label: a public-suffix-like zone
 *     label:irs          any label of the host equal to the value
 *     contains:bank      any label of the host containing the value (`mybank`, `bankofx`)
 *
 * Parsing is strict: an unknown kind, a value that is not lowercase LDH, a duplicate rule or a
 * CR is an [IllegalArgumentException] naming the line. The file ships with the app, so a bad
 * file is a build bug, and a list that half-loaded would deny less than it says. The login service
 * imports the same file and the same vectors (test resources `vault/denylist-vectors.txt`).
 */
class Denylist private constructor(
    private val builtIn: List<Rule>,
    /** Owner-added hosts, each a parsed [GrantHost]. */
    val ownerHosts: Set<String>,
    /** The vault server's host, once setup has added it. */
    val serverHost: String?,
) {

    enum class Kind(val word: String) { HOST("host"), SUFFIX("suffix"), LABEL("label"), CONTAINS("contains") }

    /** One rule. Values are lowercase LDH, checked by [parseRules]. */
    data class Rule(val kind: Kind, val value: String) {
        fun denies(host: String): Boolean = when (kind) {
            Kind.HOST, Kind.SUFFIX -> GrantHost.matches(host, value)
            Kind.LABEL -> host.split('.').any { it == value }
            Kind.CONTAINS -> host.split('.').any { it.contains(value) }
        }

        override fun toString() = "${kind.word}:$value"
    }

    companion object {
        /** The asset's name; the app reads it from `assets/`, the tests from `src/main/assets`. */
        const val ASSET = "vault-denylist-v1.txt"

        /** The rules in [text], or [IllegalArgumentException] for any line that is not exactly one. */
        fun parseRules(text: String): List<Rule> {
            require(!text.contains('\r')) { "denylist: CR in file (LF line endings only)" }
            val seen = HashSet<Rule>()
            val out = ArrayList<Rule>()
            text.split('\n').forEachIndexed { i, line ->
                if (line.isEmpty() || line.startsWith("#")) return@forEachIndexed
                val colon = line.indexOf(':')
                require(colon > 0) { "denylist line ${i + 1}: no kind" }
                val word = line.substring(0, colon)
                val value = line.substring(colon + 1)
                val kind = Kind.entries.firstOrNull { it.word == word }
                    ?: throw IllegalArgumentException("denylist line ${i + 1}: unknown kind")
                val ok = when (kind) {
                    Kind.HOST -> GrantHost.parse(value) != null
                    Kind.SUFFIX -> value.length <= GrantHost.MAX_BYTES && GrantHost.parseLabels(value, minLabels = 1) != null
                    Kind.LABEL, Kind.CONTAINS -> GrantHost.validLabel(value)
                }
                require(ok) { "denylist line ${i + 1}: bad ${kind.word} value" }
                val rule = Rule(kind, value)
                require(seen.add(rule)) { "denylist line ${i + 1}: duplicate rule" }
                out += rule
            }
            require(out.isNotEmpty()) { "denylist: no rules" }
            return out
        }

        /** The list as shipped: built-in rules only. Throws as [parseRules] does. */
        fun builtIn(text: String): Denylist = Denylist(parseRules(text), emptySet(), null)
    }

    /** The built-in rules, for the parity test and the settings screen. */
    val rules: List<Rule> get() = builtIn

    /**
     * True when [host] may not be granted. A host that is not a valid request host is denied:
     * fail closed, and the parser is the same one the request went through.
     */
    fun denies(host: String): Boolean {
        val h = GrantHost.parse(host) ?: return true
        if (builtIn.any { it.denies(h) }) return true
        if (ownerHosts.any { GrantHost.matches(h, it) }) return true
        return serverHost != null && GrantHost.matches(h, serverHost)
    }

    fun allows(host: String): Boolean = !denies(host)

    /** With the owner's [host] added, or null when it is not a valid host. */
    fun withOwnerHost(host: String): Denylist? =
        GrantHost.parse(host)?.let { Denylist(builtIn, ownerHosts + it, serverHost) }

    /** Without the owner's [host]. Built-in rules and the server host stay. */
    fun withoutOwnerHost(host: String): Denylist = Denylist(builtIn, ownerHosts - host, serverHost)

    /**
     * With the vault server's host, from its URL or bare host, or null when no host can be read
     * from it. An IP-literal server gives null: request hosts and item URIs that are IP literals
     * are refused anyway (GrantHost.parse, ItemRules), so there is nothing left to deny.
     */
    fun withServer(url: String): Denylist? =
        GrantHost.fromUri(url)?.let { Denylist(builtIn, ownerHosts, it) }
}
