package com.ritwick.sudostamp

import com.ritwick.sudostamp.Fuzz.str
import com.ritwick.sudostamp.Fuzz.u32
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Random

/**
 * Properties of the secret-request parsers (SecretProtocol) over seeded random input (FuzzSupport):
 *
 *  - parseHello and parseRequest never throw, whatever the bytes;
 *  - parseRequest accepts exactly what a reference written without its code accepts (five SSH
 *    strings and nothing after; kind "input"; a name of 1..64 identifier characters; a reason of
 *    at most 2048 bytes that the description rules keep; a P-256 point; a DER-looking signature
 *    of at most 72 bytes), over requests built from valid and hostile fields.
 */
class SecretFuzzTest {

    private val pkR = Hpke.encode(java.security.KeyPairGenerator.getInstance("EC").apply {
        initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }.generateKeyPair().public as java.security.interfaces.ECPublicKey)

    private fun reader(body: ByteArray) = AgentProtocol.Reader(byteArrayOf(27) + body).also { it.skipType() }

    /** The reference: the rules as the design states them, not as SecretProtocol codes them. */
    private fun refAccepts(fields: List<ByteArray>?, trailing: Boolean): Boolean {
        if (fields == null || fields.size != 5 || trailing) return false
        val (kind, name, why, key, sig) = fields
        if (!kind.contentEquals("input".toByteArray())) return false
        if (name.isEmpty() || name.size > 64) return false
        if (!name.all { val c = it.toInt().toChar(); c.isLetterOrDigit() && c.code < 128 || c in "._@+-" }) return false
        if (why.size > 2048 || AgentProtocol.displayText(why) == null) return false
        if (key.size != 65 || key[0] != 4.toByte() || !onCurveRef(key)) return false
        if (sig.isEmpty() || sig.size > 72 || sig[0] != 0x30.toByte()) return false
        return true
    }

    private fun onCurveRef(k: ByteArray): Boolean {
        val p = java.math.BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
        val b = java.math.BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
        val x = java.math.BigInteger(1, k.copyOfRange(1, 33))
        val y = java.math.BigInteger(1, k.copyOfRange(33, 65))
        if (x >= p || y >= p) return false
        return y.pow(2).mod(p) == x.pow(3).subtract(x.multiply(java.math.BigInteger.valueOf(3))).add(b).mod(p)
    }

    private fun field(r: Random, i: Int): ByteArray = when (r.nextInt(6)) {
        0, 1, 2 -> when (i) {                                       // mostly valid, so acceptance is exercised
            0 -> "input".toByteArray()
            1 -> ByteArray(1 + r.nextInt(64)) { "abcXYZ019._@+-"[r.nextInt(14)].code.toByte() }
            2 -> "reason ${r.nextInt()}".toByteArray()
            3 -> pkR
            else -> byteArrayOf(0x30) + Fuzz.bytes(r, r.nextInt(72))
        }
        3 -> Fuzz.bytes(r, r.nextInt(80))
        4 -> when (i) {                                             // near misses
            0 -> listOf("Input", "input ", "unseal", "").random(r).toByteArray()
            1 -> ByteArray(r.nextInt(70)) { (32 + r.nextInt(96)).toByte() }
            2 -> ByteArray(2040 + r.nextInt(16)) { 'a'.code.toByte() }
            3 -> pkR.copyOf().also { it[1 + r.nextInt(64)] = r.nextInt(256).toByte() }
            else -> ByteArray(r.nextInt(80)) { 0x30 }
        }
        else -> ByteArray(0)
    }

    private fun <T> List<T>.random(r: Random) = this[r.nextInt(size)]

    @Test
    fun `random bytes never throw`() {
        Fuzz.run("secret.random", 0x5EC1) { _, r ->
            val b = Fuzz.bytes(r, r.nextInt(300))
            SecretProtocol.parseHello(reader(b))
            SecretProtocol.parseRequest(reader(b))
        }
    }

    @Test
    fun `lying lengths never throw`() {
        Fuzz.run("secret.lies", 0x5EC2) { _, r ->
            val lie = Fuzz.LIES[r.nextInt(Fuzz.LIES.size)]
            val b = str("input") + u32(lie) + Fuzz.bytes(r, r.nextInt(64))
            SecretProtocol.parseRequest(reader(b))
            SecretProtocol.parseHello(reader(u32(lie) + Fuzz.bytes(r, r.nextInt(64))))
        }
    }

    @Test
    fun `parseRequest agrees with the reference`() {
        Fuzz.run("secret.reference", 0x5EC3) { _, r ->
            val n = if (r.nextInt(10) == 0) r.nextInt(7) else 5
            val fields = List(n) { field(r, it) }
            val trailing = r.nextInt(10) == 0
            val body = fields.fold(ByteArray(0)) { acc, f -> acc + str(f) } + if (trailing) Fuzz.bytes(r, 1 + r.nextInt(4)) else ByteArray(0)
            val got = SecretProtocol.parseRequest(reader(body))
            assertEquals("fields=${fields.map { it.size }} trailing=$trailing", refAccepts(fields, trailing), got != null)
            if (got != null) {
                assertArrayEquals(fields[2], got.whyRaw)
                assertArrayEquals(fields[3], got.pkR)
                assertArrayEquals(fields[4], got.sigH)
            }
        }
    }
}
