package com.ritwick.sudostamp

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.Collections

/** Small network helpers shared by the service and the activity. */
object Net {

    /** The phone's site-local IPv4 address -- the value the host must dial. Enumerating
     *  interfaces needs no permission, and a fixed address is the one piece of setup
     *  the user otherwise has to discover by hand.
     *
     *  Wi-Fi first: mobile carriers commonly hand out 10.x addresses too, which are just
     *  as "site-local", and showing the cellular one would point the host at nothing. */
    fun localIp(): Inet4Address? = try {
        Collections.list(NetworkInterface.getNetworkInterfaces())
            .filter { it.isUp && !it.isLoopback }
            .sortedBy { if (it.name.startsWith("wlan")) 0 else 1 }
            .flatMap { Collections.list(it.inetAddresses) }
            .filterIsInstance<Inet4Address>()
            .firstOrNull { it.isSiteLocalAddress }
    } catch (e: Exception) {
        null
    }

    /** True for an address a LAN peer can have: RFC 1918, a unique-local IPv6 address
     *  (fc00::/7: what home routers hand out), link-local, or loopback.
     *
     *  Java's isSiteLocalAddress() is true for IPv6 only in the long-deprecated fec0::/10,
     *  so a router's fd.. address would be refused as "internet" without the explicit
     *  fc00::/7 test. A global IPv6 address is deliberately NOT local. */
    fun isLanAddress(a: InetAddress): Boolean =
        (a is Inet4Address && a.isSiteLocalAddress) || a.isLinkLocalAddress || a.isLoopbackAddress || isUniqueLocal(a)

    fun isUniqueLocal(a: InetAddress): Boolean =
        a is Inet6Address && (a.address[0].toInt() and 0xFE) == 0xFC

    /** An address and prefix length the phone holds on a Wi-Fi or Ethernet network. */
    data class Prefix(val address: InetAddress, val length: Int)

    /**
     * Whether a connection from [peer], arriving at the phone's [local] address, may be served.
     *
     * Version 1 accepted any RFC 1918, unique-local or link-local source on ANY interface: a
     * carrier's 10.x network on mobile data, or another device on a VPN (Tailscale's fd7a::/48
     * is unique-local) could put approval prompts on screen. Now the connection must have
     * arrived on an address the phone holds on Wi-Fi or Ethernet ([lan], read from the
     * system's own view of its networks), the peer must be inside that address's subnet, and
     * it must still be a LAN-range address. Loopback only in a debug build (adb forward);
     * in a release build any app on the phone could otherwise connect.
     */
    fun allowedPeer(local: InetAddress, peer: InetAddress, lan: List<Prefix>, allowLoopback: Boolean): Boolean {
        if (peer.isLoopbackAddress || local.isLoopbackAddress) {
            return allowLoopback && peer.isLoopbackAddress && local.isLoopbackAddress
        }
        if (!isLanAddress(peer)) return false
        return lan.any { p -> p.address.address.contentEquals(local.address) && inPrefix(peer, p) }
    }

    fun inPrefix(a: InetAddress, p: Prefix): Boolean {
        val x = a.address
        val y = p.address.address
        if (x.size != y.size || p.length < 0 || p.length > x.size * 8) return false
        val full = p.length / 8
        for (i in 0 until full) if (x[i] != y[i]) return false
        val rest = p.length % 8
        if (rest == 0) return true
        val mask = (0xFF shl (8 - rest)) and 0xFF
        return (x[full].toInt() and mask) == (y[full].toInt() and mask)
    }

    /** The phone's addresses on Wi-Fi and Ethernet networks (not mobile data, not VPNs). */
    @Suppress("DEPRECATION")   // allNetworks: there is no non-callback replacement
    fun lanPrefixes(ctx: Context): List<Prefix> = try {
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        cm.allNetworks.flatMap { n ->
            val caps = cm.getNetworkCapabilities(n) ?: return@flatMap emptyList()
            val lan = (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) &&
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            if (!lan) return@flatMap emptyList()
            cm.getLinkProperties(n)?.linkAddresses.orEmpty().map { Prefix(it.address, it.prefixLength) }
        }
    } catch (e: Exception) {
        emptyList()   // fail closed: no known LAN means no connection is served
    }

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
     * Returns that address, or [v4] when no stable IPv6 one exists (no IPv6, no ULA prefix,
     * or privacy addresses only).
     */
    fun stableAddress(v4: InetAddress?, v6: List<Inet6Address>): InetAddress? {
        val linkLocal = v6.firstOrNull { it.isLinkLocalAddress } ?: return v4
        val iid = linkLocal.address.copyOfRange(8, 16)
        return v6.firstOrNull { isUniqueLocal(it) && it.address.copyOfRange(8, 16).contentEquals(iid) } ?: v4
    }

    /** "host:port" for [a] ("[fd..]:7777" for IPv6), in the compressed form people read. */
    fun hostPort(a: InetAddress?, port: Int): String = when (a) {
        null -> "unknown:$port"
        is Inet6Address -> "[${compress(a.address)}]:$port"
        else -> "${a.hostAddress}:$port"
    }

    /** The Wi-Fi interface's IPv6 addresses, for [stableAddress]. */
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
    fun stable(): InetAddress? = stableAddress(localIp(), localV6())

    /**
     * An endpoint as it goes into pairing ([Pairing.ENDPOINT_BYTES]): 16 address bytes, IPv4
     * as ::ffff:a.b.c.d, then the port. Bytes, not text: Java and Python spell IPv6 addresses
     * differently, and a comparison of spellings would fail between honest ends.
     */
    fun endpoint(a: InetAddress, port: Int): ByteArray {
        val addr = when (a) {
            is Inet4Address -> ByteArray(10) + byteArrayOf(-1, -1) + a.address
            else -> a.address
        }
        return addr + byteArrayOf((port ushr 8).toByte(), port.toByte())
    }

    /** RFC 5952 text for a 16-byte IPv6 address: lowercase, the longest zero run as "::". */
    fun compress(a: ByteArray): String {
        val g = IntArray(8) { ((a[it * 2].toInt() and 0xFF) shl 8) or (a[it * 2 + 1].toInt() and 0xFF) }
        var bestAt = -1; var bestLen = 1
        var i = 0
        while (i < 8) {
            if (g[i] != 0) { i++; continue }
            var j = i
            while (j < 8 && g[j] == 0) j++
            if (j - i > bestLen) { bestAt = i; bestLen = j - i }
            i = j
        }
        if (bestAt < 0) return g.joinToString(":") { Integer.toHexString(it) }
        val head = g.copyOfRange(0, bestAt).joinToString(":") { Integer.toHexString(it) }
        val tail = g.copyOfRange(bestAt + bestLen, 8).joinToString(":") { Integer.toHexString(it) }
        return "$head::$tail"
    }
}
