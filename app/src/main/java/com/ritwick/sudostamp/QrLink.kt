package com.ritwick.sudostamp

import java.util.Base64

/**
 * The link a computer's pairing QR code holds:
 *
 *     https://sudostamp.ritwickverma.dev/pair#1.<S>.<L>
 *
 * S: the pairing secret ([Pairing.QR_SECRET_BYTES] bytes), L: the computer's name (printable
 * ASCII), both base64url without padding. Both live after the '#', which a browser never sends
 * to the site: if the link opens in a browser instead of here, the secret still stays on the
 * phone. The host is SudoStamp's own site (it publishes the app-link proof), not anyone else's.
 *
 * From the pairing page's "Open in SudoStamp" button (a browser opened the link: the app was not
 * yet verified for it) the same text comes as the query parameter `k` of an intent, which no
 * browser loads; one or the other, never both.
 *
 * Network text, from a camera: parsed exactly or not at all. Pure Kotlin, so it is unit-tested
 * without Android; the activity hands over the parts of its Intent's Uri.
 */
object QrLink {
    const val HOST = "sudostamp.ritwickverma.dev"
    const val PATH = "/pair"
    private const val VERSION = "1"
    private const val MAX_LABEL = 32

    class Link(val secret: ByteArray, val label: String)

    /** [path] with or without its trailing slash; [fragment] and [k] already decoded. */
    fun parse(scheme: String?, host: String?, path: String?, fragment: String?, k: String? = null): Link? {
        if (scheme != "https" || host != HOST || (path != PATH && path != "$PATH/")) return null
        if (fragment != null && k != null) return null
        val parts = (fragment ?: k)?.split('.') ?: return null
        if (parts.size != 3 || parts[0] != VERSION) return null
        val secret = decode(parts[1]) ?: return null
        if (secret.size != Pairing.QR_SECRET_BYTES) return null
        val raw = decode(parts[2]) ?: return null
        if (raw.size > MAX_LABEL) return null
        return Link(secret, Pairing.cleanLabel(raw))
    }

    /** What a computer puts in its code: [parse] reads it back. Used by the tests. */
    fun build(secret: ByteArray, label: String): String =
        "https://$HOST$PATH#$VERSION.${encode(secret)}.${encode(label.toByteArray(Charsets.US_ASCII))}"

    private val dec = Base64.getUrlDecoder()
    private val enc = Base64.getUrlEncoder().withoutPadding()

    private fun encode(b: ByteArray): String = enc.encodeToString(b)

    /** Canonical base64url only: the alphabet, no padding, and nothing that decodes the same
     *  from two spellings (re-encoding gives back the input). */
    private fun decode(t: String): ByteArray? {
        if (t.length > 64 || t.any { !(it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_') }) return null
        val b = runCatching { dec.decode(t) }.getOrNull() ?: return null
        return b.takeIf { encode(it) == t }
    }
}
