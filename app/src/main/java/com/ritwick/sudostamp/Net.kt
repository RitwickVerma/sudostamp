package com.ritwick.sudostamp

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.Collections

/** Small network helpers shared by the service (notification text) and the activity. */
object Net {

    /** The phone's site-local IPv4 address -- the value the host must dial. Enumerating
     *  interfaces needs no permission, and a fixed address is the one piece of setup
     *  the user otherwise has to discover by hand.
     *
     *  Wi-Fi first: mobile carriers commonly hand out 10.x addresses too, which are just
     *  as "site-local", and showing the cellular one would point the host at nothing. */
    fun localIp(): String = try {
        Collections.list(NetworkInterface.getNetworkInterfaces())
            .filter { it.isUp && !it.isLoopback }
            .sortedBy { if (it.name.startsWith("wlan")) 0 else 1 }
            .flatMap { Collections.list(it.inetAddresses) }
            .filterIsInstance<Inet4Address>()
            .firstOrNull { it.isSiteLocalAddress }
            ?.hostAddress ?: "unknown"
    } catch (e: Exception) {
        "unknown"
    }

    /** True for an address a LAN peer can have: RFC 1918, a unique-local IPv6 address
     *  (fc00::/7: what home routers hand out), link-local, or loopback (an `adb forward`
     *  arrives from 127.0.0.1). Everything else is the internet.
     *
     *  Java's isSiteLocalAddress() is true for IPv6 only in the long-deprecated fec0::/10,
     *  so a router's fd.. address would be refused as "internet" without the explicit
     *  fc00::/7 test. A global IPv6 address is deliberately NOT local: the listener must
     *  never be reachable, nor serve a request, from the internet. */
    fun isLan(a: InetAddress): Boolean =
        a.isSiteLocalAddress || a.isLinkLocalAddress || a.isLoopbackAddress || isUniqueLocal(a)

    fun isUniqueLocal(a: InetAddress): Boolean =
        a is Inet6Address && (a.address[0].toInt() and 0xFE) == 0xFC

    /**
     * The address a computer should keep for this phone: one that survives the router
     * handing out a new IPv4 lease. pam_rssh takes a literal address, not a name, so the
     * address itself has to stay put.
     *
     * A unique-local IPv6 address built from the phone's Wi-Fi hardware address does: it
     * does not depend on DHCP, and the router's fd.. prefix is generated once. Android also
     * holds short-lived "temporary" addresses on the same prefix, which Java cannot tell
     * apart by flag -- but a stable address shares its 64-bit interface identifier with the
     * link-local address, and a temporary one is random. That match is the test.
     *
     * Returns "host:port" ("[fd..]:7777" for IPv6), or the IPv4 address when no stable IPv6
     * one exists (no IPv6, no ULA prefix, or privacy addresses only).
     */
    fun stableHostPort(v4: String, v6: List<Inet6Address>, port: Int): String {
        val linkLocal = v6.firstOrNull { it.isLinkLocalAddress } ?: return "$v4:$port"
        val iid = linkLocal.address.copyOfRange(8, 16)
        val stable = v6.firstOrNull { isUniqueLocal(it) && it.address.copyOfRange(8, 16).contentEquals(iid) }
            ?: return "$v4:$port"
        return "[${stable.hostAddress!!.substringBefore('%')}]:$port"
    }

    /** The Wi-Fi interface's IPv6 addresses, for [stableHostPort]. */
    fun localV6(): List<Inet6Address> = try {
        Collections.list(NetworkInterface.getNetworkInterfaces())
            .filter { it.isUp && !it.isLoopback }
            .sortedBy { if (it.name.startsWith("wlan")) 0 else 1 }
            .firstOrNull { nic -> Collections.list(nic.inetAddresses).any { it is Inet6Address && it.isLinkLocalAddress } }
            ?.let { nic -> Collections.list(nic.inetAddresses).filterIsInstance<Inet6Address>() }
            ?: emptyList()
    } catch (e: Exception) {
        emptyList()
    }

    /** What to show and hand out as this phone's address. */
    fun hostPort(port: Int): String = stableHostPort(localIp(), localV6(), port)
}
