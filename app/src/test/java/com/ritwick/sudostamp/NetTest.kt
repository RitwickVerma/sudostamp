package com.ritwick.sudostamp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.Inet6Address
import java.net.InetAddress

/** Who the listener serves, and which address it tells a computer to keep. */
class NetTest {

    private fun ip(s: String) = InetAddress.getByName(s)
    private fun v6(s: String) = ip(s) as Inet6Address

    @Test
    fun `private, link-local and loopback addresses are LAN-range`() {
        for (a in listOf("192.168.1.10", "10.0.0.5", "172.16.0.1", "172.31.255.254",
                         "169.254.10.10", "127.0.0.1", "::1", "fe80::1")) {
            assertTrue(a, Net.isLanAddress(ip(a)))
        }
    }

    @Test
    fun `unique-local IPv6 is LAN-range - Java calls it site-local only for fec0`() {
        // The case this exists for: a router's fd.. address.
        assertFalse("Java alone gets this wrong", ip("fd6c:5c93:23:1f7e::1").isSiteLocalAddress)
        for (a in listOf("fd6c:5c93:23:1f7e:445b:9bff:fe36:628a", "fc00::1", "fdff::1")) {
            assertTrue(a, Net.isLanAddress(ip(a)))
        }
    }

    @Test
    fun `public and carrier-grade NAT addresses are not, IPv4 or IPv6`() {
        // 100.64/10 is carrier NAT: other subscribers of the same mobile carrier. fec0::/10 is
        // the deprecated IPv6 site-local range, which Java still calls site-local.
        for (a in listOf("8.8.8.8", "172.32.0.1", "100.64.0.1", "203.0.113.7", "0.0.0.0",
                         "2001:db8::1", "2a00:1450:4001::1", "fe00::1", "fbff::1", "ff02::fb", "fec0::1")) {
            assertFalse(a, Net.isLanAddress(ip(a)))
        }
    }

    @Test
    fun `an IPv4-mapped address is judged as the IPv4 address it is`() {
        // A dual-stack socket reports a v4 client as ::ffff:a.b.c.d; Java hands back an
        // Inet4Address, so the usual rules apply.
        assertTrue(Net.isLanAddress(ip("::ffff:192.168.1.5")))
        assertFalse(Net.isLanAddress(ip("::ffff:8.8.8.8")))
    }

    // ---------------------------------------------------------------- who is served

    private val wifi = listOf(
        Net.Prefix(ip("192.168.1.20"), 24),
        Net.Prefix(ip("fe80::445b:9bff:fe36:628a"), 64),
        Net.Prefix(ip("fd6c:5c93:23:1f7e:445b:9bff:fe36:628a"), 64),
    )

    @Test
    fun `a peer on the Wi-Fi subnet the connection arrived on is served`() {
        assertTrue(Net.allowedPeer(ip("192.168.1.20"), ip("192.168.1.7"), wifi, false))
        assertTrue(Net.allowedPeer(ip("fe80::445b:9bff:fe36:628a"), ip("fe80::1"), wifi, false))
        assertTrue(Net.allowedPeer(ip("fd6c:5c93:23:1f7e:445b:9bff:fe36:628a"), ip("fd6c:5c93:23:1f7e::9"), wifi, false))
    }

    @Test
    fun `a private address on another network is not - mobile data, VPN, another subnet`() {
        // A carrier's 10.x network: the connection arrives on the cellular address, which is
        // not in the Wi-Fi list at all.
        assertFalse(Net.allowedPeer(ip("10.120.4.9"), ip("10.120.4.77"), wifi, false))
        // A VPN peer (Tailscale's fd7a:115c:a1e0::/48 is unique-local) on the tunnel's address.
        assertFalse(Net.allowedPeer(ip("fd7a:115c:a1e0::5"), ip("fd7a:115c:a1e0::9"), wifi, false))
        // Arrived on the Wi-Fi address, but from outside its subnet (routed in).
        assertFalse(Net.allowedPeer(ip("192.168.1.20"), ip("192.168.2.7"), wifi, false))
        assertFalse(Net.allowedPeer(ip("fd6c:5c93:23:1f7e:445b:9bff:fe36:628a"), ip("fd00::9"), wifi, false))
        // And nothing at all when the phone has no Wi-Fi or Ethernet network.
        assertFalse(Net.allowedPeer(ip("192.168.1.20"), ip("192.168.1.7"), emptyList(), false))
    }

    @Test
    fun `a public peer is refused even inside an on-link prefix`() {
        val global = listOf(Net.Prefix(ip("2001:db8:1:2::20"), 64))
        assertFalse(Net.allowedPeer(ip("2001:db8:1:2::20"), ip("2001:db8:1:2::7"), global, false))
    }

    @Test
    fun `loopback only in a debug build`() {
        assertFalse(Net.allowedPeer(ip("127.0.0.1"), ip("127.0.0.1"), wifi, false))
        assertTrue(Net.allowedPeer(ip("127.0.0.1"), ip("127.0.0.1"), wifi, true))
        assertFalse("never mixed", Net.allowedPeer(ip("192.168.1.20"), ip("127.0.0.1"), wifi, true))
    }

    @Test
    fun `prefix arithmetic`() {
        assertTrue(Net.inPrefix(ip("10.1.2.3"), Net.Prefix(ip("10.0.0.0"), 8)))
        assertFalse(Net.inPrefix(ip("11.1.2.3"), Net.Prefix(ip("10.0.0.0"), 8)))
        assertTrue(Net.inPrefix(ip("192.168.1.129"), Net.Prefix(ip("192.168.1.128"), 25)))
        assertFalse(Net.inPrefix(ip("192.168.1.127"), Net.Prefix(ip("192.168.1.128"), 25)))
        assertFalse("families never match", Net.inPrefix(ip("fd00::1"), Net.Prefix(ip("10.0.0.0"), 8)))
        assertFalse("bad length", Net.inPrefix(ip("10.0.0.1"), Net.Prefix(ip("10.0.0.0"), 33)))
    }

    @Test
    fun `IPv6 text is the compressed form people and Python read`() {
        assertEquals("fd6c:5c93:23:1f7e:445b:9bff:fe36:628a", Net.compress(ip("fd6c:5c93:23:1f7e:445b:9bff:fe36:628a").address))
        assertEquals("fd00::1", Net.compress(ip("fd00::1").address))
        assertEquals("::1", Net.compress(ip("::1").address))
        assertEquals("fe80::", Net.compress(ip("fe80::").address))
        assertEquals("first longest zero run", "1:0:0:2::3", Net.compress(ip("1:0:0:2:0:0:0:3").address))
        assertEquals("a single zero group is not shortened", "1:0:2:3:4:5:6:7", Net.compress(ip("1:0:2:3:4:5:6:7").address))
        assertEquals("[fd00::1]:7777", Net.hostPort(ip("fd00::1"), 7777))
        assertEquals("192.168.1.2:7777", Net.hostPort(ip("192.168.1.2"), 7777))
    }

    // ---------------------------------------------------------------- stable address

    private fun sh(v6s: List<Inet6Address>, port: Int) = Net.hostPort(Net.stableAddress(ip("192.168.86.14"), v6s), port)

    private val linkLocal = v6("fe80::445b:9bff:fe36:628a")
    private val stable = v6("fd6c:5c93:23:1f7e:445b:9bff:fe36:628a")           // same interface id
    private val tempA = v6("fd6c:5c93:23:1f7e:71dd:8575:3a54:10d4")             // random (privacy)
    private val tempB = v6("fd6c:5c93:23:1f7e:ffc0:a838:3bd4:f22")

    @Test
    fun `the stable address is the unique-local one sharing the link-local interface id`() {
        assertEquals("[fd6c:5c93:23:1f7e:445b:9bff:fe36:628a]:7777",
            sh(listOf(tempA, tempB, linkLocal, stable), 7777))
    }

    @Test
    fun `order does not matter and temporaries are never chosen`() {
        assertEquals("[fd6c:5c93:23:1f7e:445b:9bff:fe36:628a]:7777",
            sh(listOf(stable, linkLocal, tempB, tempA), 7777))
    }

    @Test
    fun `without a matching address it is IPv4, never a temporary`() {
        // Privacy addresses only (no stable one visible): a temporary expires within a day.
        assertEquals("192.168.86.14:7777", sh(listOf(linkLocal, tempA, tempB), 7777))
        assertEquals("192.168.86.14:7777", sh(emptyList(), 7777))
        assertEquals("192.168.86.14:7777", sh(listOf(tempA), 7777))
    }

    @Test
    fun `a global address is never offered - the listener only serves the LAN`() {
        val global = v6("2001:db8:1:2:445b:9bff:fe36:628a")
        assertEquals("192.168.86.14:7777", sh(listOf(linkLocal, global), 7777))
    }
}
