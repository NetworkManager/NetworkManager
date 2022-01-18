libnm-platform
==============

A static helper library that provides `NMPlatform` and other utils.
This is NetworkManager's internal netlink library, but also contains
helpers for sysfs, ethtool and other kernel APIs.

`NMPlaform` is also a cache of objects of the netlink API: `NMPCache`
and `NMPObject`. These objects are used throughout NetworkManager
also for generally tracking information about these types. For example,
`NMPlatformIP4Address` (the public part of a certain type of `NMPObject`)
is not only used to track platform addresses from netlink in the cache,
but to track information about IPv4 addresses in general.

This depends on the following helper libraries

  - [../libnm-std-aux/](../libnm-std-aux/)
  - [../libnm-base/](../libnm-base/)
  - [../libnm-glib-aux/](../libnm-glib-aux/)
  - [../libnm-udev-aux/](../libnm-udev-aux/)
  - [../libnm-log-core/](../libnm-log-core/)
  - [../linux-headers/](../linux-headers/)


TODO and Bugs
=============

IPv6 Multi-hop Routes
---------------------

NMPlatform has a cache (dictionary) with netlink objects, which can also be augmented
with additional information like the WifiData or the udev device. A dictionary requires
that objects have an identity, which they can be compared and hash. In other words,
a set of properties that determines that the object is something distinctly recognizable.

Route routes and routing policy routes, from point of view of kernel there is not
a simple set of properties/attributes that determine the identity of the route/rule. Rather,
most attributes are part of the ID, but not all. See `NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID`
and `NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID`.

For routes, we currently ignore all multi-hop routes (ECMP). For IPv4, that is fine because
kernel also treats the next hops (of any number) to be the part of the ID of a route. For
example, you can see in `ip route` two IPv4 routes that only differ by their next-hops.
As NetworkManager currently doesn't configure multi-hop routes, ignoring those routes and
not caching them is no problem.

For IPv6 routes that is different. When you add two IPv6 routes that only differ by their
next hops, then kernel will merge them into a multi-hop route (as you can see in `ip -6 route`).
Likewise, if you remove a (single or multi-hop) route, then kernel will "subtract" those
hops from the multi-hop route. In a way, kernel always mangles the result into a multi-hop route.
If you logically consider the hops of an IPv6 part of the identity of a route, then adding a route,
can create a new (because distinct as by their ID) route while removing the previously existing route
(without sending a RTM_DELROUTE message). As NetworkManager currently ignores all multi-hop routes,
this easily leads to an inconsistent cache, because NetworkManager does not understand that the
addition/removal of an IPv6 route, interferes with an entirely different route (from point of view of
the identity).
So you could say the problem is that the ID of a route changes (by merging the next hops). But that
makes no sense, because the ID identifies the route, it cannot change without creating a different
route. So the alternative to see this problem is that adding a route can create a different route
and deleting the previous one, but there are not sufficient netlink events to understand which
route got mangled (short of searching the cache). But also, the RTM_NEWROUTE command no longer
necessarily results in the addition of the route we requested and a RTM_DELROUTE event does
not necessarily notify about the route that was removed (rather, it notifies about the part
that got subtracted).

Another way to see kernel's bogus behavior is to pretend that there are only single-hop routes.
That makes everything simple, the only speciality is that a RTM_NEWROUTE now can contain
(with this point of view of the identity) multiple routes, one for each hop.

To solve the problem of platform cache inconsistencies for IPv6 routes, NetworkManager should
only honor IPv6 single-path routes, but with the twist that one RTM_NEWROUTE can announce multiple
routes at once.

This alternative view that we should implement is possibly a deviation from kernel's view.
Usually we avoid modelling things differently than kernel, but in this case it makes more
sense as this is more how it appears on the netlink API (based on the events that we get).

See also: https://bugzilla.redhat.com/show_bug.cgi?id=1837254#c20
