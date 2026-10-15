package com.ritwick.sudostamp

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

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

    // agent -> client
    const val SSH2_AGENT_FAILURE = 5
    const val SSH2_AGENT_IDENTITIES_ANSWER = 12
    const val SSH2_AGENT_SIGN_RESPONSE = 14

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

    /**
     * Why a sign request must be refused without asking the user, or null if it may be
     * put to them. [ourKey] is our public key blob.
     */
    fun refusal(keyBlob: ByteArray, data: ByteArray, ourKey: ByteArray): String? = when {
        !keyBlob.contentEquals(ourKey) -> "sign request for an unknown key"
        data.size != CHALLENGE_BYTES -> "refusing to sign ${data.size} bytes: not a pam_rssh challenge"
        else -> null
    }

    /** IDENTITIES_ANSWER carrying exactly one key. */
    fun identitiesAnswer(keyBlob: ByteArray, comment: String): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(SSH2_AGENT_IDENTITIES_ANSWER)
        putInt(o, 1)                                     // one key
        putBlob(o, keyBlob)
        putBlob(o, comment.toByteArray(Charsets.UTF_8))
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

        @Throws(IOException::class)
        fun blob(): ByteArray {
            if (pos + 4 > buf.size) throw EOFException("truncated length")
            val n = ((buf[pos].toInt() and 0xFF) shl 24) or
                    ((buf[pos + 1].toInt() and 0xFF) shl 16) or
                    ((buf[pos + 2].toInt() and 0xFF) shl 8) or
                    (buf[pos + 3].toInt() and 0xFF)
            pos += 4
            if (n < 0 || pos + n > buf.size) throw EOFException("truncated blob")
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
