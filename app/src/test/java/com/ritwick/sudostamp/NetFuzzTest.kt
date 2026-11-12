package com.ritwick.sudostamp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.Random

/**
 * Net decides which peers may put an approval prompt on the screen (allowedPeer) and which
 * address a computer keeps for the phone (stableAddress, endpoint). Seeded random addresses of
 * every family the LAN throws up (RFC 1918, CGNAT, loopback, link-local with and without a scope
 * id, unique-local, global, IPv4-mapped) are checked against references written from the RFCs'
 * prefixes with no shared code, and against the properties that matter whatever the code does:
 *
 *  - a peer outside the LAN ranges is never served (loopback aside, and only when allowed);
 *  - a peer is served only inside a prefix of an address the phone holds, of the same family;
 *  - a bad prefix length is "no match", never an exception;
 *  - endpoint() and compress() round-trip.
 */
class NetFuzzTest {

    // ------------------------------------------------------------------ generators

    private fun v4(a: Int, b: Int, c: Int, d: Int): InetAddress = InetAddress.getByAddress(byteArrayOf(a.toByte(), b.toByte(), c.toByte(), d.toByte()))

    private fun v6(bytes: ByteArray, scope: Int = 0): InetAddress =
        if (scope == 0) InetAddress.getByAddress(bytes) else Inet6Address.getByAddress(null, bytes, scope)

    private fun rnd8(r: Random) = r.nextInt(256)

    private fun flip(b: ByteArray, r: Random): ByteArray = b.copyOf().also { val at = r.nextInt(it.size); it[at] = (it[at].toInt() xor (1 shl r.nextInt(8))).toByte() }

    /** Every family, weighted towards the boundaries where a prefix test goes wrong. */
    private fun address(r: Random): InetAddress = when (r.nextInt(18)) {
        0 -> v4(rnd8(r), rnd8(r), rnd8(r), rnd8(r))
        1 -> v4(10, rnd8(r), rnd8(r), rnd8(r))
        2 -> v4(172, 15 + r.nextInt(4), rnd8(r), rnd8(r))              // 172.15 .. 172.18: both sides of 172.16/12
        3 -> v4(172, 16 + r.nextInt(16), rnd8(r), rnd8(r))
        4 -> v4(192, 167 + r.nextInt(3), rnd8(r), rnd8(r))              // 192.167 .. 192.169
        5 -> v4(169, 253 + r.nextInt(3), rnd8(r), rnd8(r))              // around 169.254/16
        6 -> v4(127, rnd8(r), rnd8(r), rnd8(r))
        7 -> v4(100, 63 + r.nextInt(3) * 32 - r.nextInt(2), rnd8(r), rnd8(r))   // carrier-grade NAT edges
        8 -> v6(Fuzz.bytes(r, 16).also { it[0] = (0x20 + r.nextInt(0x20)).toByte() })                      // global 2000::/3
        9 -> v6(Fuzz.bytes(r, 16).also { it[0] = 0xFE.toByte(); it[1] = (0x80 + r.nextInt(0x40)).toByte() }, if (r.nextBoolean()) 0 else 1 + r.nextInt(30))
        10 -> v6(Fuzz.bytes(r, 16).also { it[0] = (0xFC + r.nextInt(2)).toByte() })                          // unique-local
        11 -> v6(Fuzz.bytes(r, 16).also { it[0] = (0xFA + r.nextInt(6)).toByte() })                          // around fc00::/7
        12 -> v6(ByteArray(16).also { it[10] = -1; it[11] = -1; for (k in 12..15) it[k] = rnd8(r).toByte() })   // v4-mapped
        13 -> v6(ByteArray(16).also { it[15] = 1 })                                                        // ::1
        14 -> v6(Fuzz.bytes(r, 16).also { it[0] = 0xFE.toByte(); it[1] = (0xC0 + r.nextInt(0x40)).toByte() })  // fec0::/10, deprecated site-local
        15 -> v6(Fuzz.bytes(r, 16).also { it[0] = 0xFF.toByte() })                                           // multicast
        16 -> v6(ByteArray(16).also { for (k in 12..15) it[k] = rnd8(r).toByte() })                          // ::a.b.c.d (IPv4-compatible)
        else -> v6(Fuzz.bytes(r, 16))
    }

    private fun prefixOf(a: InetAddress, r: Random): Net.Prefix {
        val bits = a.address.size * 8
        val len = when (r.nextInt(8)) {
            0 -> -1 - r.nextInt(5)
            1 -> bits + 1 + r.nextInt(9)
            2 -> Int.MIN_VALUE
            3 -> Int.MAX_VALUE
            else -> r.nextInt(bits + 1)
        }
        return Net.Prefix(a, len)
    }

    // ------------------------------------------------------------------ references

    private fun unsigned(b: ByteArray) = BigInteger(1, b)

    /** Whether [a] shares its first [len] bits with [net], by big-number shifting. */
    private fun sameBits(a: ByteArray, net: ByteArray, len: Int): Boolean {
        if (a.size != net.size || len < 0 || len > a.size * 8) return false
        val drop = a.size * 8 - len
        return unsigned(a).shiftRight(drop) == unsigned(net).shiftRight(drop)
    }

    private fun inRange(a: ByteArray, base: String, len: Int): Boolean {
        val n = InetAddress.getByName(base).address
        return sameBits(a, n, len)
    }

    /** The ranges a LAN peer can have, straight from the RFCs. Java's own predicates are not used. */
    private fun lanReference(a: InetAddress): Boolean {
        val b = a.address
        return if (b.size == 4)
            inRange(b, "10.0.0.0", 8) || inRange(b, "172.16.0.0", 12) || inRange(b, "192.168.0.0", 16) ||
                inRange(b, "169.254.0.0", 16) || inRange(b, "127.0.0.0", 8)
        else
            inRange(b, "fe80::", 10) || inRange(b, "fc00::", 7) || inRange(b, "::1", 128)
    }

    private fun loopbackReference(a: InetAddress): Boolean =
        a.address.let { if (it.size == 4) inRange(it, "127.0.0.0", 8) else inRange(it, "::1", 128) }

    // ------------------------------------------------------------------ address classes

    @Test
    fun `isLanAddress matches the RFC ranges for every address family`() {
        Fuzz.run("net/lan", 21) { _, r ->
            val a = address(r)
            assertEquals(a.toString(), lanReference(a), Net.isLanAddress(a))
            // fec0::/10 is deprecated site-local, global and CGNAT space are the internet.
            if (a is Inet6Address && a.address[0] == 0xFE.toByte() && (a.address[1].toInt() and 0xC0) == 0xC0) assertFalse(Net.isLanAddress(a))
            assertEquals(a.toString(), a is Inet6Address && (a.address[0].toInt() and 0xFE) == 0xFC, Net.isUniqueLocal(a))
        }
    }

    // ------------------------------------------------------------------ prefixes

    @Test
    fun `inPrefix is a prefix comparison and a bad length or family never matches`() {
        Fuzz.run("net/prefix", 22) { _, r ->
            val a = address(r)
            // Half the time a neighbour of `a`, so the boundary bit is what decides.
            val b = if (r.nextBoolean()) address(r) else InetAddress.getByAddress(flip(a.address, r))
            val p = prefixOf(b, r)
            val want = sameBits(a.address, p.address.address, p.length)
            assertEquals("${a.hostAddress} in ${p.address.hostAddress}/${p.length}", want, Net.inPrefix(a, p))
            if (a.address.size != p.address.address.size) assertFalse("families never mix", Net.inPrefix(a, p))
            if (p.length < 0 || p.length > p.address.address.size * 8) assertFalse(Net.inPrefix(a, p))
            if (a.address.size == p.address.address.size && p.length == 0) assertTrue("/0 is the whole family", Net.inPrefix(a, p))
            assertTrue("an address is in its own /bits", Net.inPrefix(a, Net.Prefix(a, a.address.size * 8)))
        }
    }

    // ------------------------------------------------------------------ allowedPeer

    @Test
    fun `allowedPeer serves a peer only on a held address, inside its subnet, in a LAN range`() {
        Fuzz.run("net/allowedPeer", 23) { _, r ->
            // Arrival addresses and peers drawn near each other so the subnet test is exercised
            // in both directions and not just rejected by family.
            val local = address(r)
            val peer = if (r.nextInt(3) == 0) address(r) else local.address.let { x ->
                x.copyOf().also { if (r.nextBoolean()) it[it.size - 1 - r.nextInt(minOf(3, it.size))] = rnd8(r).toByte() }.let { InetAddress.getByAddress(it) }
            }
            val lan = (0 until r.nextInt(5)).map { Net.Prefix(if (r.nextInt(3) == 0) address(r) else local, run { val bits = local.address.size * 8; if (r.nextInt(6) == 0) prefixOf(local, r).length else r.nextInt(bits + 1) }) }
            val allowLoopback = r.nextBoolean()

            val got = Net.allowedPeer(local, peer, lan, allowLoopback)

            val loop = loopbackReference(peer) || loopbackReference(local)
            val want = if (loop) allowLoopback && loopbackReference(peer) && loopbackReference(local)
            else lanReference(peer) && lan.any { p -> p.address.address.contentEquals(local.address) && sameBits(peer.address, p.address.address, p.length) }
            assertEquals("local=${local.hostAddress} peer=${peer.hostAddress} lan=${lan.map { "${it.address.hostAddress}/${it.length}" }} loop=$allowLoopback", want, got)

            // Properties that hold whatever the reference says:
            if (got && !allowLoopback) assertFalse("loopback served in a release build", peer.isLoopbackAddress || local.isLoopbackAddress)
            if (got && !loop) {
                assertTrue("served a peer outside every LAN range: ${peer.hostAddress}", lanReference(peer))
                assertTrue("served a peer with no subnet on the arrival address", lan.any { it.address.address.contentEquals(local.address) })
            }
            if (lan.isEmpty() && !loop) assertFalse("no known LAN must serve nobody", got)
            // More networks can only let more peers in.
            if (got) assertTrue(Net.allowedPeer(local, peer, lan + Net.Prefix(local, 0), allowLoopback))
        }
    }

    @Test
    fun `a global or carrier address is never served, whatever the prefixes say`() {
        Fuzz.run("net/global", 24, weight = 50) { _, r ->
            val peer = if (r.nextBoolean()) v6(Fuzz.bytes(r, 16).also { it[0] = (0x20 + r.nextInt(0x20)).toByte() })
                       else v4(r.nextInt(100), rnd8(r), rnd8(r), rnd8(r)).takeUnless { lanReference(it) } ?: v4(8, 8, 8, 8)
            if (lanReference(peer)) return@run
            val local = address(r)
            // Even a prefix of length 0 on the arrival address, and loopback allowed.
            val lan = listOf(Net.Prefix(local, 0), Net.Prefix(local, local.address.size * 8), Net.Prefix(peer, 0))
            assertFalse(peer.hostAddress, Net.allowedPeer(local, peer, lan, allowLoopback = true))
        }
    }

    // ------------------------------------------------------------------ text and endpoint

    private fun compressReference(b: ByteArray): String {
        val g = (0 until 8).map { ((b[it * 2].toInt() and 0xFF) shl 8) or (b[it * 2 + 1].toInt() and 0xFF) }
        var run: Pair<Int, Int>? = null                    // longest run of >= 2 zero groups, leftmost on a tie
        for (len in 8 downTo 2) {
            for (start in 0..8 - len) if (run == null && (start until start + len).all { g[it] == 0 }) run = start to len
            if (run != null) break
        }
        fun hex(l: List<Int>) = l.joinToString(":") { Integer.toHexString(it) }
        return if (run == null) hex(g) else hex(g.subList(0, run.first)) + "::" + hex(g.subList(run.first + run.second, 8))
    }

    @Test
    fun `compress is RFC 5952 text and reads back to the same 16 bytes`() {
        Fuzz.run("net/compress", 25) { _, r ->
            val b = when (r.nextInt(4)) {
                0 -> Fuzz.bytes(r, 16)
                1 -> Fuzz.bytes(r, 16).also { for (k in 0 until 8) if (r.nextBoolean()) { it[k * 2] = 0; it[k * 2 + 1] = 0 } }      // many zero groups
                2 -> ByteArray(16).also { for (k in 0 until 3) it[r.nextInt(16)] = rnd8(r).toByte() }                             // mostly zero
                else -> ByteArray(16).also { if (r.nextBoolean()) it[15] = 1 }                                                    // ::, ::1
            }
            val text = Net.compress(b)
            assertEquals(compressReference(b), text)
            assertEquals("lowercase", text.lowercase(), text)
            assertFalse("no triple colon", text.contains(":::"))
            assertTrue("at most one ::", text.split("::").size <= 2)
            // Read it back with Java's own parser (bracketed so IPv4-mapped forms stay v6).
            assertArrayEquals(text, b, Inet6Address.getByName("[$text]").let { if (it is Inet4Address) ByteArray(10) + byteArrayOf(-1, -1) + it.address else it.address })
        }
    }

    @Test
    fun `endpoint is 18 bytes, mapped for IPv4, and decodes back to the address and port`() {
        Fuzz.run("net/endpoint", 26) { _, r ->
            val a = address(r)
            val port = if (r.nextInt(4) == 0) listOf(0, 1, 255, 256, 7777, 32767, 32768, 65535)[r.nextInt(8)] else r.nextInt(65536)
            val e = Net.endpoint(a, port)
            assertEquals(Pairing.ENDPOINT_BYTES, e.size)
            assertEquals(port, ((e[16].toInt() and 0xFF) shl 8) or (e[17].toInt() and 0xFF))
            val back = InetAddress.getByAddress(e.copyOfRange(0, 16))
            assertEquals("a v4 address travels as ::ffff:a.b.c.d and comes back as itself", a.address.toList(), back.address.toList())
            if (a is Inet4Address) {
                assertArrayEquals(ByteArray(10), e.copyOfRange(0, 10))
                assertEquals(-1, e[10].toInt()); assertEquals(-1, e[11].toInt())
            }
            val text = Net.hostPort(a, port)
            if (a is Inet6Address) {
                assertTrue(text, text.startsWith("[") && text.endsWith("]:$port"))
                assertArrayEquals(a.address, InetAddress.getByName(text.substring(1, text.length - ("]:$port").length)).address)
            } else assertEquals("${a.hostAddress}:$port", text)
        }
        assertEquals("unknown:7777", Net.hostPort(null, 7777))
    }

    // ------------------------------------------------------------------ the address a computer keeps

    @Test
    fun `stableAddress is the unique-local address that shares the link-local interface id, else IPv4`() {
        Fuzz.run("net/stable", 27) { _, r ->
            val iid = Fuzz.bytes(r, 8)
            val prefix = Fuzz.bytes(r, 8).also { it[0] = 0xFD.toByte() }
            fun withIid(head: ByteArray, id: ByteArray) = InetAddress.getByAddress(head + id) as Inet6Address
            val list = ArrayList<Inet6Address>()
            if (r.nextInt(5) != 0) list += withIid(byteArrayOf(0xFE.toByte(), 0x80.toByte(), 0, 0, 0, 0, 0, 0), iid)             // link-local
            repeat(r.nextInt(4)) { list += withIid(prefix, Fuzz.bytes(r, 8)) }                                                     // temporary ULAs
            if (r.nextInt(3) != 0) list += withIid(prefix, iid)                                                                    // the stable one
            if (r.nextInt(4) == 0) list += withIid(Fuzz.bytes(r, 8).also { it[0] = 0x20 }, iid)                                    // global, same iid
            if (r.nextInt(6) == 0) list += withIid(byteArrayOf(0xFE.toByte(), 0xC0.toByte(), 0, 0, 0, 0, 0, 0), iid)               // deprecated site-local
            list.shuffle(r)
            val four = if (r.nextInt(5) == 0) null else v4(192, 168, rnd8(r), rnd8(r))

            val got = Net.stableAddress(four, list)

            val ll = list.firstOrNull { it.address[0] == 0xFE.toByte() && (it.address[1].toInt() and 0xC0) == 0x80 }
            val want: InetAddress? = if (ll == null) four
            else list.firstOrNull { (it.address[0].toInt() and 0xFE) == 0xFC && it.address.copyOfRange(8, 16).contentEquals(ll.address.copyOfRange(8, 16)) } ?: four
            assertEquals(want?.hostAddress, got?.hostAddress)
            // Never a temporary, never a global address, never link-local.
            if (got != null && got !== four) {
                assertTrue("only a unique-local address is offered", Net.isUniqueLocal(got))
                assertTrue("sharing the link-local interface id", ll != null && got.address.copyOfRange(8, 16).contentEquals(ll.address.copyOfRange(8, 16)))
            }
        }
    }
}
