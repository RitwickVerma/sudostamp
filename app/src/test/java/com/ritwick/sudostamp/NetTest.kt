package com.ritwick.sudostamp

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

/** The listener refuses every client [Net.isLan] rejects, before reading a byte. */
class NetTest {

    private fun ip(s: String) = InetAddress.getByName(s)

    @Test
    fun `private, link-local and loopback peers are LAN`() {
        for (a in listOf("192.168.1.10", "10.0.0.5", "172.16.0.1", "172.31.255.254",
                         "169.254.10.10", "127.0.0.1")) {
            assertTrue(a, Net.isLan(ip(a)))
        }
    }

    @Test
    fun `public and carrier-grade NAT peers are not`() {
        // 100.64/10 is carrier NAT: other subscribers of the same mobile carrier.
        for (a in listOf("8.8.8.8", "172.32.0.1", "100.64.0.1", "203.0.113.7", "0.0.0.0")) {
            assertFalse(a, Net.isLan(ip(a)))
        }
    }
}
