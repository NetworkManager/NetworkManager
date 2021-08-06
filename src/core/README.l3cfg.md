L3Cfg Rework
============

NMDevice is complex. Together with NMManager, NMDevice does too much.

The goal is to rework the IP configuration (Layer 3) to be a more separate
part of the code that is better maintainable, easier to understand and
extend and more correct.

Current Situation
-----------------

- [NMManager](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/nm-manager.c):
  this is the main object (a singleton) that drives most things.
  Among many other things, it creates NMDevice instances and coordinates.

- [NMDevice](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/devices/nm-device.c):
  this represents a device. This is a subclass of NMDBusObject,
  it is thus directly exported on D-Bus (as D-Bus objects like
  `/org/freedesktop/NetworkManager/Devices/1`).
  It also manages all aspects of the device. It has an overall state
  (`NM_DEVICE_STATE`) but lots of more specific states (e.g. current state
  of DHCP configuration). As always, the hardest part in programming are
  stateful objects, and NMDevice has *a lot* of state. The code is huge and
  hard to understand and the class has (too) many responsibilities. \
  \
  NMDevice also has subclasses, which are determined based on the "device type". That
  means, there are subclasses like NMDeviceEthernet and NMDeviceBridge. As such, the
  subclasses also export additional D-Bus interfaces. These subclasses also handle
  the Layer 2 specific aspects of the device. For this aspect, delegation probably
  would have been a better choice. On the other hand, IP configuration is almost entirely
  managed by the parent class. Which is good, because the IP configuration is common to all
  device types, but is bad because NMDevice already does so many things.

- [NMIP4Config](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/nm-ip4-config.c) (and NMIP6Config):
  these are also subclasses of NMDBusObject
  and exported on D-Bus on paths like `/org/freedesktop/NetworkManager/IP4Config/1`.
  The device's `IP4Config` property refers to these objects. They contain
  the runtime IP information of that device. I don't think these objects
  should exist on the D-Bus API, as NMDevice could directly expose these properties.
  But for historic reasons, such is our D-Bus API.
  Other than that, NMIP4Config objects are also used internally for tracking
  IP configuration. For example, [when](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/dhcp/nm-dhcp-nettools.c#L563)
  we receive a DHCP lease, we construct a NMIP4Config object with the addresses, DNS settings,
  and so on. These
  instances are then [tracked by](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/devices/nm-device.c#L519)
  NMDevice, and [merged](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/devices/nm-device.c#L8928)
  into an instance that is then exposed on D-Bus. As such, this class has two
  mostly independent purposes.

- [NMDhcpClient](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/dhcp/nm-dhcp-client.c):
  our DHCP "library". It's a simple object with a clear API that
  abstracts most of the complexity of handling DHCP. But still, NMDevice
  needs to drive the DHCP client instance. Meaning, it needs to create (start) and stop
  them and hook up signals for changes (new lease) and timeout. This is mostly
  fine and unavoidable. The point is that while specific tasks are well abstracted
  (like the details of DHCP), there is still some state in NMDevice that is related
  to manage these tasks. DHCP is one of many such tasks, like also
  link local addresses, SLAAC or LLDP.
  This leads to the increased complexity of NMDevice, which manages a large variety
  of such tasks.

### Problems:

1. first the sheer code size of [nm-device.c](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/devices/nm-device.c#L19030).
   It's hard to understand and maintain, and this results in misbehaviours. Also, features that should be easy to implement
   are not. Also, there are inefficiencies that are hard to fix.

2. NMDevice and NMIP4Config are both exported on D-Bus while having other responsibilities.
   Being subclasses of NMDBusObject, they are glued to the D-Bus API. For example, NMIP4Config is
   also used for other purposes (for tracking IP configuration internally).

3. NMDevice simply does too much. IP configuration should be a separate, encapsulated
   API to make allow NMDevice to be smaller and the IP configuration part better
   testable, understandable and smaller too.

4. in the current model, NMDevice can be related to zero, one or two ifindexes. For example,
   for ethernet devices, there is commonly only one actual netdev device (and one ifindex).
   For OVS devices, there is no ifindex. For NMDeviceModem or NMDeviceBluetooth there is
   a NMDevice instance that has initially no ifindex (it represents the tty serial port
   or the bluetooth device) but during activation it gets and ip ifindex. With PPPoE,
   the ethernet device can even have two ifindexes (one for the underlying ethernet and
   one for the PPP device). That is all utterly confusing, inconsistent and limited.
   For example, not all interfaces you see in `ip link` can be found in the D-Bus API.
   The D-Bus API also does not give access to the ifindex (which is the real identifier
   for a netdev devices). It only exposes the IpInterface name. That should be improved too,
   but even such seemingly simple things are not done for years, because it's not trivially
   clear what the right ifindex is.
   Also a device instance on D-Bus significantly changes its meaning when it activates/deactivates
   and it starts/stops being responsible for an ifindex.
   In the future there should be devices that represent exactly one netdev device (an ifindex)
   and devices that don't have an ifindex. That is follow up work and hinted by
   [rhbz#1066703](https://bugzilla.redhat.com/show_bug.cgi?id=1066703). But simplifying
   the IP configuration is a requisite before addressing that rework.
   With this we will have controller and controlled devices. That means, a controller devices
   (that for example represents a bluetooth device) will need to configure IP address on the
   controlled IP device. That would be doable by injecting the IP config on that device,
   but as the device already does so much, it would be better if this would be a separate
   IP configuration manager for that ifindex.

5. NMIP4Config exports properties on D-Bus like [AddressData](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/introspection/org.freedesktop.NetworkManager.IP4Config.xml#L26).
   which are the currently configured IP addresses. These should be directly obtained
   from the NMPlatform cache, which contains the correct list of addresses as kernel
   exposes them via rtnetlink. Instead, whenever there are changes in platform we
   [generate](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/devices/nm-device.c#L14223)
   an NMIP4Config instance, then we merge, intersect and subtract this captured information
   with the IP configs we want to configure. Finally we merge them together again
   and sync the result to platform. This is bad, wrong and inefficient.
   We must not mix "what is configured" with "what we want to configure". The current
   approach also re-generates these IP config instance whenever something in platform changes.
   That does not scale. If we have any hope to handle thousands of routes, this needs to change.

6. The NMIP4Config objects are mutable, and they are heavily mutated. When we create an NMIP4Config
   instance that represent a DHCP lease, we will [subtract](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/devices/nm-device.c#L14236)
   addresses that were externally removed. That is wrong, because during a reapply we
   will need to know these addresses again. The solution for that is not to mutate this
   data, but track whether IP addresses are removed separately.

7. NMDevice also does ACD, but it can only do it for addresses received via DHCP.
   It implicitly also does ACD for IPv4LL, but that is via using the n_ipv4ll library.
   It would be good to have an option that we can configure IPv4LL for any address.
   Also, if you manually configure an address like 192.168.2.5 (for which we don't do
   ACD) and the same address is obtained via DHCP, then doing ACD for the address is wrong.
   There needs to be link-wide view of the addresses, and not only looking at individual
   addresses when deciding to do ACD.

8. As IP configuration is done by NMDevice, VPN connections have limited capabilities
   in this regard.
   When a VPN has IP addresses, then it injects them into NMDevice by
   [providing](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/devices/nm-device.c#L13696)
   an NMIP4Config. However, that means VPNs cannot do DHCP or IPv4LL, because it can
   only inject known configuration. That would be very useful for example with a tap
   device with openvpn. The real problem here is that NMVpnConnection are
   treated special, when they should be more like devices. That should be reworked in the future,
   by reworking VPN plugins. Regardless, having IP configuration handled by NMDevice is limiting.

9. NetworkManager currently supports `ipv4.method` which can be "manual", "disabled" or
   "auto". This scheme does not allow for example to enable IPv4LL together with DHCPv4.
   As a special case, you can configure `ipv4.method=auto` together with static
   addresses in `ipv4.addresses`, so combining DHCP and static addressing works. But in general,
   this scheme is limited. In the future we should have more flexible schemes, where
   addressing methods can be independently enabled or disabled. Also, we currently
   have `ipv4.may-fail`, but that is limited as well. For example,
   `ipv4.may-fail=yes` and `ipv6.may-fail=yes` still means that at least one of the
   address families must succeed. That makes sense for certain use cases, but it
   means, you cannot have truly best-effort, opportunistic DHCP with this way.
   As workaround for that there is `ipv4.dhcp-timeout=infinity`. In
   general it is not only useful to enable methods independently, we also configure
   independently whether they are required or optional (and possibly, that they are optional
   but at least one of several optional methods must succeed). Anyway. The point
   is there is a need to make IP configuration more flexible. Currently it is not.
   Such a seemingly simple extension would be surprisingly difficult to implement
   because [the code](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/devices/nm-device.c#L6616) is
   all over the place. The way how NMDevice tracks the overall activation state is
   hard to understand. This should be improved and possibly could be improved in a
   smaller refactoring effort. But instead of a smaller effort, we will use the big hammer
   with L3Cfg rework.

10. There are two classes NMIP4Config and NMIP6Config. Handling both address families is
   commonly similar, so there is lot of similar code in both. They should be unified
   so that similar code can handle both address families.


Solution and Future
-------------------

NML3Cfg work is supposed to simplify some part of NMDevice: the part related to
IP configuration. This is a huge rework of a core part of NetworkManager. Arguably,
some parts maybe could be done more evolutionary, but the fundamental problems require
to rip out NMIP4Config and replace it by something better. Doing that is a large rework
that changes NMDevice heavily. That is also the opportunity to get the smaller issues
right.

There is already a new class [NML3Cfg](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/nm-l3cfg.h#L141)
(currently unused). An NML3Cfg instance is responsible for handling IP configuration
of an ifindex. Consequently, we can ask NMNetns to [get](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/nm-netns.c#L142)
(or create) a NML3Cfg instance for an ifindex.
The idea is that there can be multiple users (NMDevice and NMVpnConnection and future controller devices)
that use the same NML3Cfg instance. Especially with a future rework of NMDevice where
a NMDevice only manages one ifindex (or none), there is a need that multiple
devices manage the IP configuration on the same device. Independent users can cooperate
to configure IP configuration on the same device. Already now with Libreswan VPN, where the VPN "injects"
its NMIP4Config in NMDevice. Or with PPPoE, where the NMDeviceEthernet is both about IP configuration
for the PPPoE device.

There is also a new class [NML3ConfigData](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/nm-l3-config-data.h).
This replaces some aspect of NMIP4Config/NMIP6Config. A NML3ConfigData object is immutable and has no real logic
(or state). It has some "logic", like comparing two NML3ConfigData instances, logging it, or merging two (immutable)
instances into a new instance. But as the class is immutable, that logic is rather simple. This class is
used to track information. As it's immutable, anybody who is interested can keep a reference
for it's own purpose. For example, NMDhcpClient will generate a NML3ConfigData with the information
of the lease. It may keep the reference, but it will also tell NMDevice about it. The NMDevice
will then itself tell NML3Cfg to accept this configuration. This works by calling
[add()/remove()](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/nm-l3cfg.c#L2654).
One NML3ConfigData can also track both IPv4 and IPv6 information. It's a general set of IP related
configuration, that has some address specific properties. Those are then duplicated for both address
families and implemented in a way to minimize code duplication and encourage to treat them the same.
As this replaces an aspect of NMIP4Config, NMIP4Config can focus on it's other purpose: to expose data on D-Bus.

What NML3Cfg then does, is to merge all NML3ConfigData, and "commit" it to platform. Thereby it knows
which addresses it configured the last time (if they no longer are to be configured, they must be removed).
This is done [here](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/nm-l3cfg.c#L3442).

As independent users should be able to cooperate, it is not appropriate that they call "commit".
Instead, they set a commit type ([here](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/nm-l3cfg.c#L3476),
and whenever something changes, NML3Cfg knows the aggregated commit type. That is necessary
because when we activate a device, we may want to preserve the existing IP configuration (e.g. after
a restart of NetworkManager). During that time is the NML3Cfg instance set to a reduced commit
mode (ASSUME).

NML3Cfg will also handle IPv4 ACD. Any user of NML3Cfg registers/unregisters NML3ConfigData instances
that should be configured. Thereby they also say whether ACD should be done for the IPv4 addresses.
NML3Cfg then keeps state for each IPv4 address, whether ACD should be performed, and whether the
address is ready to be configured. NML3Cfg does not do DHCP or similar. That is still the responsibility
of NMDevice to run a NMDhcpClient. But it does run ACD, because whether to perform ACD on an address
requires a holistic view of all addresses of that interface. For example, if you configure a static
IP address 192.168.2.5 (with ACD disabled) and you also get the same address via DHCP, then ACD should
not performed for that address (even if the user configured ACD with DHCP). Of course, that is a very
unlikely example. More likely is that NetworkManager is restarted and it leaves the addresses (that passed
ACD) configured. After restart, DHCP finds the same addresses and no new ACD should be performed. This shows
that the ACD state depends all the IP addresses on an interface,
and thus it's done by NML3Cfg. The API for this is very simple. Users enable/disable ACD during nm_l3cfg_add_config()
and receive events like [NM_L3_CONFIG_NOTIFY_TYPE_ACD_EVENT](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/nm-l3cfg.c#L303).
Another advantage is that ACD now works for any kinds of addresses. Currently it only works for addresses
from DHCP and link local addresses.

NML3Cfg does not implement or drive DHCP. However, as it already does ACD it gained it's own IPv4LL
"library": [NML3IPv4LL](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/nm-l3cfg.c#L3624).
This will replace nettools' n-ipv4ll library, because that library also does ACD internally, while we want
to use the holistic view that NML3Cfg has. What this means, is that the user (NMDevice)
can request a NML3IPv4LL handle from the NML3Cfg instance, and it just does it with a simple API.
All the user might do is to enable/disable the handle and to react to signals (if it cares to find
out whether IPv4LL fails).

The general parts of NML3Cfg are already implemented. It has unit tests and can be tested independently.
You might note that NML3Cfg is not trivial already, but the API that it provides is as simple as possible:
create immutable NML3ConfigData instance, and add/remove them. Optionally, handle the ACD events and
listen to some events. The complexity that NML3Cfg has, will lead in the same amount simplify NMDevice.

What is missing is NMDevice using this new API. Instead of creating and tracking NMIP4Config instances,
it needs to track NML3ConfigData instances. In principle that sounds simple, in practice that changes
large part of "nm-device.c".

Thereby also the state machine for NM_DEVICE_STATE will be improved. It's anyway a rewrite. This will lay the
groundwork for more flexible configuration of IP methods, with different failure modes (opportunistic or
mandatory).

What then also should be easier, to combine IPv4LL with other addressing methods. In Windows AFAIK, if you
don't get a DHCP address it will configure a IPv4LL address. That is also what RFC suggests, but which we
currently don't support.

In general, change the way how external IP addresses/routes are tracked. This merge, intersect, subtract
approach does not perform well. Currently we react on signals and it's hard to understand what happens
in response to that, or whether it's really the correct thing to do. See yourself starting from
[here](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/devices/nm-device.c#L14214).

### DHCP

Currently, when NMDhcpClient receives a lease, it emits a signal with two things: the NMIP4Config
instance (containing addresses, routes, DNS settings and other information for later use), and a string
dictionary with the DHCP lease options (they are mainly used to expose them on D-Bus). The latter is
immutable (meaning, it's not changed afterwards). That does not significantly change with L3Cfg. The
difference is that instead of NMIP4Config a NML3ConfigData instance gets created. That instance then
references the (immutable) strdict. With that, any part of the code that has access to the NML3ConfigData,
also has access to the lease options. So instead of two separate
pieces of information, the result of a lease event will only be a NML3ConfigData instance (which internally
tracks the strdict with the DHCP lease options).

Later, when NML3Cfg configures an interface, it takes all NML3ConfigData instances that were added to
it, and merges them. [Currently](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/nm-l3-config-data.c#L2693),
the merged data will not contain the lease information, but it's probably not needed anyway.

If it would be needed, the question is what happens if multiple lease informations are present
during the merge. Duplicate leases would not commonly happen, but in general, the merging algorithm
needs to take into account priorities and conflicting data.
That is done by users who call [add](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/nm-l3cfg.c#L2658)
to provide a priority for the NML3ConfigData instance.
Later, the instances get sorted by priority and merging is smart to take that into account
([here](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/nm-l3cfg.c#L2983)).

Also, we currently inject the route-metric and table into the generated NMIP4Config.
Those settings come from the connection profiles and not from DHCP. We will avoid that
by allowing the routes in NML3ConfigData to be marked as metric\_any and table\_any.
That way,the NML3ConfigData is independent (and immutable) with respect to those settings.
The same happens for example with PPP, where the modem starts PPP, and currently the
route and metric needs to be passed several layers down. But worst, those settings
can change during reapply. Currently that means we need to hack NMIP4Config with
those changes. Later, we will only tell NML3Cfg to track the NML3ConfigData with
different settings.

### DNS

DNS information is currently set in the NMIP4Config instances. That happens for example with the DNS information
from a DHCP lease, but also with the static DNS settings from the connection profile. Later, the same information
will packed in NML3ConfigData.

One nice difference is again the immutability. Currently, NMDnsManager keeps a reference to all relevant NMIP4Config instances,
but as they are mutable, it needs to [subscribe](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/6b64fac06d2f6e0d9fa530ebb1ab28d53a1c5d03/src/core/dns/nm-dns-manager.c#L275)
to changes. Later, when a NML3ConfigData instance "changes", it means it was
replaced by a different one and NMDnsManager needs to update its list of tracked NML3ConfigData. I find that
cleaner, because adding and removal to the list of NMIP4Config/NML3ConfigData happens anyway and needs to be handled.


Related Bugs
------------

* Main bug:

  - [rh#1868254](https://bugzilla.redhat.com/show_bug.cgi?id=1868254):
    "refactor NetworkManager's IP configuration done by NMDevice"

* Follow up but to improve model of devices:

  - [rh#1066703](https://bugzilla.redhat.com/show_bug.cgi?id=1066703):
    "\[RFE\] Handle parent/child relationships more cleanly"

* Flexible IP methods:

  - [rh#1791624](https://bugzilla.redhat.com/show_bug.cgi?id=1791624):
    "NetworkManager must not remove used bridge"

* Improving performance issues, this will lay ground work:

  - [rh#1847125](https://bugzilla.redhat.com/show_bug.cgi?id=1847125):
    "\[RFE\] Improve 20% performance on creating 1000 bridge over 1000 VLANs"

  - [rh#1861527](https://bugzilla.redhat.com/show_bug.cgi?id=1861527):
    "Excessive memory and CPU usage on a router with IPv6 BGP feed"

  - [rh#1753677](https://bugzilla.redhat.com/show_bug.cgi?id=1753677):
    "High cpu usage while non-controlled interface is mangling tc filters"

