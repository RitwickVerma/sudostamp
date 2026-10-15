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
    fun `private, link-local and loopback peers are LAN`() {
        for (a in listOf("192.168.1.10", "10.0.0.5", "172.16.0.1", "172.31.255.254",
                         "169.254.10.10", "127.0.0.1", "::1", "fe80::1")) {
            assertTrue(a, Net.isLan(ip(a)))
        }
    }

    @Test
    fun `unique-local IPv6 is LAN - Java calls it site-local only for fec0`() {
        // The case this exists for: a router's fd.. address.
        assertFalse("Java alone gets this wrong", ip("fd6c:5c93:23:1f7e::1").isSiteLocalAddress)
        for (a in listOf("fd6c:5c93:23:1f7e:445b:9bff:fe36:628a", "fc00::1", "fdff::1")) {
            assertTrue(a, Net.isLan(ip(a)))
        }
    }

    @Test
    fun `public and carrier-grade NAT peers are not, IPv4 or IPv6`() {
        // 100.64/10 is carrier NAT: other subscribers of the same mobile carrier.
        for (a in listOf("8.8.8.8", "172.32.0.1", "100.64.0.1", "203.0.113.7", "0.0.0.0",
                         "2001:db8::1", "2a00:1450:4001::1", "fe00::1", "fbff::1", "ff02::fb")) {
            assertFalse(a, Net.isLan(ip(a)))
        }
    }

    @Test
    fun `an IPv4-mapped peer is judged as the IPv4 address it is`() {
        // A dual-stack socket reports a v4 client as ::ffff:a.b.c.d; Java hands back an
        // Inet4Address, so the usual rules apply.
        assertTrue(Net.isLan(ip("::ffff:192.168.1.5")))
        assertFalse(Net.isLan(ip("::ffff:8.8.8.8")))
    }

    // ---------------------------------------------------------------- stable address

    private val linkLocal = v6("fe80::445b:9bff:fe36:628a")
    private val stable = v6("fd6c:5c93:23:1f7e:445b:9bff:fe36:628a")           // same interface id
    private val tempA = v6("fd6c:5c93:23:1f7e:71dd:8575:3a54:10d4")             // random (privacy)
    private val tempB = v6("fd6c:5c93:23:1f7e:ffc0:a838:3bd4:f22")

    @Test
    fun `the stable address is the unique-local one sharing the link-local interface id`() {
        assertEquals("[fd6c:5c93:23:1f7e:445b:9bff:fe36:628a]:7777",
            Net.stableHostPort("192.168.86.14", listOf(tempA, tempB, linkLocal, stable), 7777))
    }

    @Test
    fun `order does not matter and temporaries are never chosen`() {
        assertEquals("[fd6c:5c93:23:1f7e:445b:9bff:fe36:628a]:7777",
            Net.stableHostPort("192.168.86.14", listOf(stable, linkLocal, tempB, tempA), 7777))
    }

    @Test
    fun `without a matching address it is IPv4, never a temporary`() {
        // Privacy addresses only (no stable one visible): a temporary expires within a day.
        assertEquals("192.168.86.14:7777", Net.stableHostPort("192.168.86.14", listOf(linkLocal, tempA, tempB), 7777))
        assertEquals("192.168.86.14:7777", Net.stableHostPort("192.168.86.14", emptyList(), 7777))
        assertEquals("192.168.86.14:7777", Net.stableHostPort("192.168.86.14", listOf(tempA), 7777))
    }

    @Test
    fun `a global address is never offered - the listener only serves the LAN`() {
        val global = v6("2001:db8:1:2:445b:9bff:fe36:628a")
        assertEquals("192.168.86.14:7777", Net.stableHostPort("192.168.86.14", listOf(linkLocal, global), 7777))
    }
}
