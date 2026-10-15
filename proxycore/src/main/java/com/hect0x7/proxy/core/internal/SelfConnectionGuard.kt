package com.hect0x7.proxy.core.internal

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketAddress

internal fun isSelfConnection(localAddress: SocketAddress?, remoteAddress: SocketAddress?): Boolean {
  val local = localAddress as? InetSocketAddress ?: return false
  val remote = remoteAddress as? InetSocketAddress ?: return false
  if (remote.hostString.equals("localhost", ignoreCase = true)) return true
  val remoteIp = remote.address ?: return false
  val localIp = local.address ?: return false
  // Allow Tailscale CGNAT range (100.64.0.0/10): Tailscale userspace NAT
  // makes remote tailnet peers appear with CGNAT source addresses;
  // blocking them breaks legitimate cross-device proxying over Tailscale.
  if (isTailscaleIp(remoteIp)) return false
  return remoteIp.isLoopbackAddress || remoteIp == localIp
}

/** 100.64.0.0/10 (100.64.0.0 - 100.127.255.255), IPv4 only. */
private fun isTailscaleIp(ip: InetAddress): Boolean {
  val bytes = ip.address
  if (bytes.size != 4) return false
  val b0 = bytes[0].toInt() and 0xFF
  val b1 = bytes[1].toInt() and 0xFF
  return b0 == 100 && b1 in 64..127
}
