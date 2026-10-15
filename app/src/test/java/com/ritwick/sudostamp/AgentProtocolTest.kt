package com.ritwick.sudostamp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.nio.charset.StandardCharsets

/**
 * The framing/parse layer is part of the trusted path: AgentService hands every byte a
 * remote client sends to AgentProtocol, and every reply it writes goes through it too.
 * It had NO unit tests -- a parse bug here is exactly the "nothing crashes, auth silently
 * fails on real hardware" failure mode SshSigTest was written against.
 */
class AgentProtocolTest {

    private fun write(body: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        AgentProtocol.writeFrame(out, body)
        return out.toByteArray()
    }

    @Test
    fun frameRoundTripsThroughWriteFrameAndReadFrame() {
        val body = byteArrayOf(AgentProtocol.SSH2_AGENTC_REQUEST_IDENTITIES.toByte())
        assertArrayEquals(body, AgentProtocol.readFrame(ByteArrayInputStream(write(body))))
    }

    @Test
    fun cleanEofReturnsNullNotAnException() {
        assertNull(AgentProtocol.readFrame(ByteArrayInputStream(ByteArray(0))))
    }

    @Test
    fun eofInsideTheLengthFieldClosesCleanly() {
        // 2 of the 4 length bytes, then EOF. readInt cannot distinguish this from a
        // clean hangup and does not need to: either way the server closes the socket
        // and answers nothing -- fail-closed, never a signature, never a crash.
        assertNull(AgentProtocol.readFrame(ByteArrayInputStream(byteArrayOf(0, 0))))
    }

    @Test
    fun zeroAndNegativeFrameLengthsAreRejected() {
        assertThrows(IOException::class.java) {
            AgentProtocol.readFrame(ByteArrayInputStream(int32Bytes(0)))
        }
        assertThrows(IOException::class.java) {
            AgentProtocol.readFrame(ByteArrayInputStream(int32Bytes(-1)))
        }
    }

    @Test
    fun framesOver64KiBAreRejected() {
        // Refuse before allocating: a claimed 64K+ frame is never legitimate.
        assertThrows(IOException::class.java) {
            AgentProtocol.readFrame(ByteArrayInputStream(int32Bytes(64 * 1024 + 1)))
        }
    }

    @Test
    fun bodyShorterThanTheDeclaredLengthIsRejected() {
        val s = ByteArrayInputStream(byteArrayOf(0, 0, 0, 5, 1, 2))   // claims 5, sends 2
        assertThrows(EOFException::class.java) { AgentProtocol.readFrame(s) }
    }

    @Test
    fun identitiesAnswerCarriesExactlyOneKeyWithItsComment() {
        val key = "keyblob".toByteArray(StandardCharsets.UTF_8)
        val frame = AgentProtocol.identitiesAnswer(key, "sudostamp")
        val r = AgentProtocol.Reader(frame)
        assertEquals(AgentProtocol.SSH2_AGENT_IDENTITIES_ANSWER, r.type())
        r.skipType()
        assertEquals(1, r.int32())
        assertArrayEquals(key, r.blob())
        assertArrayEquals("sudostamp".toByteArray(StandardCharsets.UTF_8), r.blob())
    }

    @Test
    fun signResponseWrapsTheSignatureBlobExactlyOnce() {
        val sig = byteArrayOf(9, 8, 7)
        val frame = AgentProtocol.signResponse(sig)
        val r = AgentProtocol.Reader(frame)
        assertEquals(AgentProtocol.SSH2_AGENT_SIGN_RESPONSE, r.type())
        r.skipType()
        assertArrayEquals(sig, r.blob())
        assertEquals("no trailing bytes", 4 + sig.size, frame.size - 1)
    }

    @Test
    fun failureFrameIsA1ByteFailure() {
        val f = AgentProtocol.failure()
        assertEquals(1, f.size)
        assertEquals(AgentProtocol.SSH2_AGENT_FAILURE.toByte(), f[0])
    }

    @Test
    fun readerRejectsTruncatedBlobsInsteadOfReadingGarbage() {
        val r = AgentProtocol.Reader(byteArrayOf(11, 0, 0, 0, 4, 1))   // declares 4, has 1
        r.skipType()
        assertThrows(IOException::class.java) { r.blob() }
    }

    @Test
    fun readerRejectsBlobsWithNegativeDeclaredLength() {
        val r = AgentProtocol.Reader(
            byteArrayOf(11, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())
        )
        r.skipType()
        assertThrows(IOException::class.java) { r.blob() }
    }

    @Test
    fun readerRejectsTruncatedInts() {
        val r = AgentProtocol.Reader(byteArrayOf(11, 0, 0))
        r.skipType()
        assertThrows(IOException::class.java) { r.int32() }
    }

    // ------------------------------------------------------------- sign policy

    private val ourKey = byteArrayOf(1, 2, 3, 4)

    @Test
    fun aPamRsshChallengeForOurKeyMayBePutToTheUser() {
        assertNull(AgentProtocol.refusal(ourKey, ByteArray(32), ourKey))
    }

    @Test
    fun aSignRequestForAnotherKeyIsRefused() {
        assertNotNull(AgentProtocol.refusal(byteArrayOf(9), ByteArray(32), ourKey))
    }

    @Test
    fun anythingButA32ByteChallengeIsRefused() {
        // An SSH userauth blob: string(session id, 32 bytes) || byte 50 || user || ...
        // It STARTS like a challenge, so the length check is what stops it.
        val userauth = ByteArray(4 + 32 + 1 + 40)
        // An `ssh-keygen -Y sign` / git signature: begins with the "SSHSIG" magic.
        val sshsig = "SSHSIG".toByteArray() + ByteArray(60)
        for ((name, data) in listOf(
            "empty" to ByteArray(0),
            "31 bytes" to ByteArray(31),
            "33 bytes" to ByteArray(33),
            "ssh userauth" to userauth,
            "sshsig" to sshsig,
        )) {
            assertNotNull("must refuse $name", AgentProtocol.refusal(ourKey, data, ourKey))
        }
    }

    private fun int32Bytes(v: Int): ByteArray = byteArrayOf(
        (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()
    )
}
