Rework `NMIP[46]Config` for `next` branch
=========================================

The `next` branch is a large rework of internals, how IP configuration is done by `NMDevice`.

Previously, there are two `GObject`s named `NMIP4Config` and `NMIP6Config`. These
serve different purposes:

1) They are data containers that can track IP configuration. As such, `NMDevice`
   and various parts (like `NMDhcpClient`) create them, pass them around and
   mutate/merge them to track the IP configuration.

2) They are also subclasses of `NMDBusObject` and exported on D-Bus as
   `/org/freedesktop/NetworkManager/IP4Config/1`, etc. As such, see their
   [D-Bus API](../../introspection/org.freedesktop.NetworkManager.IP4Config.xml)
   (and [for IPv6](../../introspection/org.freedesktop.NetworkManager.IP6Config.xml)).

`next` branch will replace use 1) with `NML3ConfigData`. `NML3ConfigData` are immutable
(sealable) data containers with little logic. This leaves `NMIP4Config` to only
implement 2).

This needs to be reworked.

* Now `NMIP4Config` and `NMIP6Config` are subclasses of `NMIPConfig`. The goal
  is to treat IPv4/IPv6 similar and generically. Probably there should be very
  little code in the subclasses left and most should move to the parent classes.
  We still need separate GObject types though, because that is how `NMDBusObject`'s
  glue code can handle different D-Bus paths.

* Now `NML3Cfg` is a handle for the IP configuration parameters of a device (ifindex).
  As `NMIPConfig` mostly is about exporting the current IP configuration, it probably
  can get most of it from there (and by listening to signals to that).

* Note that `NMDevice`, `NMActiveConnection` refer `NMIP[46]Config`s, and most
  importantly, the respective D-Bus objects refer to them. As `NMVpnConnection`
  (and "org.freedesktop.NetworkManager.VPN.Connection" interface) are modeled
  as "subclasses" of `NMActiveConnection`, they also have one. That means,
  it's not entirely clear what these properties even are. For example, currently,
  `NMDevice` does a (terrible) dance of tracking external `NMIP[46]Config` objects,
  merging, intersecting and subtracting them with other `NMIP4Config` objects
  to get the merged one, which is then exported on D-Bus. That merged object
  does therefore not directly expose the IP addresses that are actually
  configured on the interface (`ip addr`), but more what NetworkManager
  wanted to configure and the (terrible) feedback loop where the platform
  addresses get synced. With `next` branch and `NML3Cfg` there is a clear distinction
  between what NetworkManager wants to configure vs. what is actually configured.
  I think for `NMDevice` and `NMActiveConnection`, the IP addresses on
  "org.freedesktop.NetworkManager.IP4Config" should expose the IP addresses
  that are actually in platform (`ip addr`). If there is a need to expose
  additional information (like things that NetworkManager wanted to configure),
  then this should be different/new API.
  On the other hand, currently `NMVpnConnection`'s `NMIP4Config` only tracks the 
  IP addresses that come from the VPN plugin. So it's much more what it wants
  to configure (from the VPN plugin), and not at all about what is configured
  on the interface.
  I think that needs to change. A `NMIPConfig` object on D-Bus exposes IP configuration
  information about an netdev interface. Period. That also means that a `NMVpnConnection`
  (which currently is like a active connection associated with the device) links to
  the same `NMIPConfig` object as the underlying device.
