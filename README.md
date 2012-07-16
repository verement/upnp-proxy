
UPnP-Proxy
==========

This is a proxy for upnpd (linux-igd) to rewrite the LOCATION field on
multihomed hosts to contain the correct interface IP address matching the
network to which each response is sent.

The Problem
-----------

According to [UPnP™ Device Architecture 1.1][UPnP] §1.3.3, “… Multi-homed
devices MUST send the search response using the same UPnP-enabled interface on
which the search request was received. **The URL specified in the LOCATION
field value MUST specify an address that is reachable on that interface.**”

[UPnP]: http://upnp.org/sdcps-and-certification/standards/

While this requirement is not actively enforced by all UPnP clients, some
devices are known not to work properly without the correct network-local IP
address in the LOCATION field.

Unfortunately, the API for libupnp (used by linux-igd) does not work well in a
multihomed environment, and there seems to be no suitable provision for
modifying the LOCATION field on a per-response basis. Consequently, we are
forced to choose the IP address of a single interface to use in all responses.

A Solution
----------

Rather than modifying libupnp to cope with this situation, this is a simple
hack to intercept each outgoing response, rewrite the LOCATION field as
appropriate for the destination, and then resend the packet.

To be useful, an iptables rule is needed to intercept outgoing packets and
redirect them to this proxy. 

For example:

    iptables -t nat -A OUTPUT  \
        --protocol udp --destination 10.0.0.0/24  \
        --match owner ! --uid-owner proxy  \
        --match u32 --u32 '4 & 0x3fff = 0'  \
                    --u32 '0 >> 22 & 0x3c @ 8 = 0x48545450'  \
        --jump REDIRECT --to-ports 7909

In this instance, `10.0.0.0/24` refers to one network of the multihomed router
for which responses should be proxied. (A separate rule may be needed for each
such network.) Also, `proxy` refers to a user that should not have its packets
intercepted, lest we end up with an infinite loop. In this case we assume the
proxy daemon will be running as this user.

The u32 filters first ensure the outgoing UDP packet is not a fragment (`4 &
0x3fff = 0`), then look into the payload of the packet to see if it starts
with "HTTP" (`0x48545450`).

When a matching packet is found, it is redirected to port 7909 on the local
host, where the proxy daemon is presumed to be listening.

Caveat Emptor
-------------

This is an experimental solution. I better solution would be to fix libupnp to
support multihoming properly.

In order to work, the proxy has to discover the original destination IP
address for each intercepted UDP packet. This turns out to be nontrivial;
currently the proxy relies on libnetfilter_conntrack to find the associated
connection. This is potentially unreliable and subject to race conditions.

In order to use libnetfilter_conntrack, the proxy requires the CAP_NET_ADMIN
Linux capability. The Makefile attempts to grant this capability to the built
executable. You may consequently want to limit the ability to execute the
daemon as appropriate.

