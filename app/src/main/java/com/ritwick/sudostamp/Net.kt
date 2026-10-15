package com.ritwick.sudostamp

import java.net.Inet4Address
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

    /** True for an address a LAN peer can have: RFC 1918, link-local, or loopback (an
     *  `adb forward` arrives from 127.0.0.1). Everything else is the internet. */
    fun isLan(a: InetAddress): Boolean =
        a.isSiteLocalAddress || a.isLinkLocalAddress || a.isLoopbackAddress
}
