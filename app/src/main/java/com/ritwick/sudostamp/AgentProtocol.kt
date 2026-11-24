package com.ritwick.sudostamp

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * The MINIMAL ssh-agent protocol. Two request types, nothing else.
 *
 * WHY SO SMALL: pam_rssh on the host is the only client. It needs to (a) list our key and
 * (b) ask for a signature. Everything else in the protocol -- add/remove identity, lock,
 * certificates -- is unreachable from that client, so implementing it would add attack
 * surface for no benefit. Unknown request types get SSH_AGENT_FAILURE.
 *
 * Frame format (both directions):
 *     uint32 length      (payload length, NOT including these 4 bytes)
 *     byte   type
 *     ...    payload
 */
object AgentProtocol {

    // client -> agent
    const val SSH2_AGENTC_REQUEST_IDENTITIES = 11
    const val SSH2_AGENTC_SIGN_REQUEST = 13
    /** Only for pairing (see Pairing.kt); pam_rssh never sends it. */
    const val SSH2_AGENTC_EXTENSION = 27

    // agent -> client
    const val SSH2_AGENT_FAILURE = 5
    const val SSH2_AGENT_SUCCESS = 6
    const val SSH2_AGENT_IDENTITIES_ANSWER = 12
    const val SSH2_AGENT_SIGN_RESPONSE = 14

    /** The extension name (SSH string) a computer sends to say what a sudo is for. Advisory: see
     *  [parseContext] and docs/DESIGN.md. */
    const val EXT_CONTEXT = "context-v1@sudostamp"

    /** The longest description payload accepted, in bytes. sudo's argv is short; more is not a description. */
    const val MAX_CONTEXT_BYTES = 2048

    /** The most code points of a description that are kept (the ellipsis included). */
    const val MAX_CONTEXT_CODE_POINTS = 512

    /** Refuse absurd frames: a real client never sends more than a few KB. */
    private const val MAX_FRAME = 64 * 1024

    /**
     * The only thing this agent will sign: a pam_rssh challenge, which is exactly 32 random
     * bytes (sign_verify.rs gen_challenge, `vec![0; 32]` filled by rand_bytes).
     *
     * WHY: without this the key is a general-purpose signing oracle. An SSH login signs a
     * structured blob that starts with the 32-byte session id and runs on for 100+ bytes;
     * an `ssh-keygen -Y` / git signature signs a blob starting "SSHSIG". If this key ever
     * ended up in an authorized_keys file or an allowed-signers list, a LAN client could
     * have the user approve one of those under the guise of a sudo. Refusing every other
     * size makes the key useless for anything but this one job -- and refuses before the
     * user is asked, so such a request never even reaches the notification.
     */
    const val CHALLENGE_BYTES = 32

    /**
     * Reads one frame, or returns null on a CLEAN disconnect (client closed between frames).
     *
     * The distinction matters: EOF between frames is the normal way a client says "I am
     * done" and must not be logged as an error, whereas a malformed frame is a real
     * protocol violation. Throwing EOFException for both made an ordinary hangup look
     * like an attack, and left the caller unable to stop looping gracefully.
     */
    @Throws(IOException::class)
    fun readFrame(input: InputStream): ByteArray? {
        val d = DataInputStream(input)
        val len = try {
            d.readInt()
        } catch (e: EOFException) {
            return null
        }
        if (len < 1 || len > MAX_FRAME) throw IOException("bad frame length $len")
        val body = ByteArray(len)
        d.readFully(body)
        return body
    }

    @Throws(IOException::class)
    fun writeFrame(out: OutputStream, body: ByteArray) {
        val d = DataOutputStream(out)
        d.writeInt(body.size)
        d.write(body)
        d.flush()
    }

    fun failure(): ByteArray = byteArrayOf(SSH2_AGENT_FAILURE.toByte())

    /** SUCCESS followed by SSH strings: how the pairing extensions answer. */
    fun success(vararg strings: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(SSH2_AGENT_SUCCESS)
        strings.forEach { putBlob(o, it) }
        return o.toByteArray()
    }

    /** An attestation chain is a few KB (3 to 5 certificates). Anything bigger than this is
     *  refused rather than sent: the answer to a LAN client stays small whatever the Keystore says. */
    private const val MAX_ATTEST_BYTES = 16 * 1024
    private const val MAX_ATTEST_CERTS = 8

    /** SUCCESS, the challenge, then each DER certificate, leaf first, as SSH strings (the answer
     *  to attest-v1); FAILURE for a chain that is empty or too big. */
    fun attestAnswer(challenge: ByteArray, chain: List<ByteArray>): ByteArray =
        if (chain.isEmpty() || chain.size > MAX_ATTEST_CERTS || chain.sumOf { it.size } > MAX_ATTEST_BYTES) failure()
        else success(challenge, *chain.toTypedArray())

    /**
     * Why a sign request must be refused without asking the user, or null if it may be put to
     * them. [knownKey]: the key it names belongs to a paired computer. An unknown key is
     * refused before anything is shown -- so a device that never paired cannot put a prompt on
     * the screen at all.
     */
    fun refusal(knownKey: Boolean, data: ByteArray): String? = when {
        !knownKey -> "sign request for a key this phone did not make for any paired computer"
        data.size != CHALLENGE_BYTES -> "refusing to sign ${data.size} bytes: not a pam_rssh challenge"
        else -> null
    }

    /** The same decision as [refusal], as the typed reason the history records. Kept beside it
     *  so the two cannot drift (AgentProtocolTest checks they agree). */
    fun refusalKind(knownKey: Boolean, data: ByteArray): Refusal? = when {
        !knownKey -> Refusal.UNKNOWN_KEY
        data.size != CHALLENGE_BYTES -> Refusal.NOT_A_CHALLENGE
        else -> null
    }

    /**
     * The description a computer sends before pam_rssh ([EXT_CONTEXT]): ONE SSH string, the
     * name having been consumed by the caller. Returns the text to show, or null for anything
     * that is not exactly that: trailing bytes, more than [MAX_CONTEXT_BYTES], malformed UTF-8
     * (a strict decoder: String(bytes) would silently turn it into U+FFFD), nothing left after
     * trimming. Never throws.
     *
     * WHY THE SCRUBBING: the text comes from a program on the LAN and is shown on a screen the
     * user trusts with a fingerprint. See [sanitize] for what is replaced and why.
     */
    fun parseContext(r: Reader): String? {
        val raw = try {
            val b = r.blob()
            if (!r.atEnd() || b.size > MAX_CONTEXT_BYTES) return null
            b
        } catch (e: IOException) {
            return null
        }
        return displayText(raw)
    }

    /** [raw] as text to show (the rules of [parseContext], minus the framing): null for
     *  malformed UTF-8 or nothing left after scrubbing. Never throws. */
    fun displayText(raw: ByteArray): String? {
        val text = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(raw)).toString()
        } catch (e: CharacterCodingException) {
            return null
        }
        return sanitize(text, MAX_CONTEXT_CODE_POINTS)
    }

    /**
     * Makes [s] safe to put in front of the user: every C0 and C1 control, DEL and the invisible
     * and bidirectional format characters become '?', so the text shown is what the bytes are
     * ("trojan source": a right-to-left override can make `rm -rf /tmp/x` read as something
     * else; a line break or ESC could fake a second line). Nothing else is changed: no collapsing
     * of spaces. Trimmed, then cut to [maxCodePoints] code points in all, the last being '…'
     * when something was cut. Null when nothing is left. Idempotent.
     */
    fun sanitize(s: String, maxCodePoints: Int): String? {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            i += Character.charCount(cp)
            sb.appendCodePoint(if (invisible(cp)) '?'.code else if (oddSpace(cp)) ' '.code else cp)
        }
        val t = sb.toString().trim()
        if (t.isEmpty()) return null
        if (t.codePointCount(0, t.length) <= maxCodePoints) return t
        return t.substring(0, t.offsetByCodePoints(0, maxCodePoints - 1)) + "…"
    }

    private fun invisible(cp: Int): Boolean = when (Character.getType(cp)) {
        // Controls, format characters (bidi, zero-width, tags, the Arabic letter mark, soft
        // hyphen), line and paragraph separators, and what is not a character at all.
        Character.CONTROL.toInt(), Character.FORMAT.toInt(), Character.LINE_SEPARATOR.toInt(),
        Character.PARAGRAPH_SEPARATOR.toInt(), Character.SURROGATE.toInt(),
        Character.PRIVATE_USE.toInt(), Character.UNASSIGNED.toInt() -> true
        // Default-ignorable or blank-looking characters that are not FORMAT: the combining
        // grapheme joiner, Hangul fillers, Khmer inherent vowels, Mongolian variation selectors,
        // variation selectors and the Braille blank.
        else -> cp == 0x034F || cp == 0x115F || cp == 0x1160 || cp == 0x3164 || cp == 0xFFA0 ||
            cp == 0x17B4 || cp == 0x17B5 || cp in 0x180B..0x180F || cp in 0xFE00..0xFE0F ||
            cp in 0xE0100..0xE01EF || cp == 0x2800
    }

    /** A space other than U+0020 (no-break, wide, thin): shown as a plain space, so a gap cannot
     *  pose as the end of a line. */
    private fun oddSpace(cp: Int): Boolean =
        cp != 0x20 && Character.getType(cp) == Character.SPACE_SEPARATOR.toInt()

    /** IDENTITIES_ANSWER listing [keyBlobs]: one key per paired computer. pam_rssh uses the
     *  one its computer pinned. */
    fun identitiesAnswer(keyBlobs: List<ByteArray>, comment: String): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(SSH2_AGENT_IDENTITIES_ANSWER)
        putInt(o, keyBlobs.size)
        for (k in keyBlobs) {
            putBlob(o, k)
            putBlob(o, comment.toByteArray(Charsets.UTF_8))
        }
        return o.toByteArray()
    }

    /** SIGN_RESPONSE carrying the SSH signature blob. */
    fun signResponse(signatureBlob: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(SSH2_AGENT_SIGN_RESPONSE)
        putBlob(o, signatureBlob)
        return o.toByteArray()
    }

    private fun putInt(o: ByteArrayOutputStream, v: Int) {
        o.write((v ushr 24) and 0xFF)
        o.write((v ushr 16) and 0xFF)
        o.write((v ushr 8) and 0xFF)
        o.write(v and 0xFF)
    }

    private fun putBlob(o: ByteArrayOutputStream, b: ByteArray) {
        putInt(o, b.size)
        o.write(b, 0, b.size)
    }

    /** Cursor over a request payload. Fails loudly rather than reading garbage. */
    class Reader(private val buf: ByteArray) {
        private var pos = 0

        /** The type byte. Does not advance. */
        fun type(): Int = buf[0].toInt() and 0xFF

        fun skipType() { pos = 1 }

        /** True when every byte has been read. */
        fun atEnd(): Boolean = pos == buf.size

        @Throws(IOException::class)
        fun blob(): ByteArray {
            if (pos + 4 > buf.size) throw EOFException("truncated length")
            val n = ((buf[pos].toInt() and 0xFF) shl 24) or
                    ((buf[pos + 1].toInt() and 0xFF) shl 16) or
                    ((buf[pos + 2].toInt() and 0xFF) shl 8) or
                    (buf[pos + 3].toInt() and 0xFF)
            pos += 4
            // Not `pos + n > size`: with n near Int.MAX_VALUE that sum overflows negative.
            if (n < 0 || n > buf.size - pos) throw EOFException("truncated blob")
            return buf.copyOfRange(pos, pos + n).also { pos += n }
        }

        @Throws(IOException::class)
        fun int32(): Int {
            if (pos + 4 > buf.size) throw EOFException("truncated int")
            val v = ((buf[pos].toInt() and 0xFF) shl 24) or
                    ((buf[pos + 1].toInt() and 0xFF) shl 16) or
                    ((buf[pos + 2].toInt() and 0xFF) shl 8) or
                    (buf[pos + 3].toInt() and 0xFF)
            pos += 4
            return v
        }
    }
}
