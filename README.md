******************
NetworkManager core daemon has moved to gitlab.freedesktop.org!

git clone https://gitlab.freedesktop.org/NetworkManager/NetworkManager.git
******************


Networking that Just Works
--------------------------

NetworkManager attempts to keep an active network connection available at all
times.  The point of NetworkManager is to make networking configuration and
setup as painless and automatic as possible.  NetworkManager is intended to
replace default route, replace other routes, set IP addresses, and in general
configure networking as NM sees fit (with the possibility of manual override as
necessary).  In effect, the goal of NetworkManager is to make networking Just
Work with a minimum of user hassle, but still allow customization and a high
level of manual network control.  If you have special needs, we'd like to hear
about them, but understand that NetworkManager is not intended for every
use-case.

NetworkManager will attempt to keep every network device in the system up and
active, as long as the device is available for use (has a cable plugged in,
the killswitch isn't turned on, etc).  Network connections can be set to
'autoconnect', meaning that NetworkManager will make that connection active
whenever it and the hardware is available.

"Settings services" store lists of user- or administrator-defined "connections",
which contain all the settings and parameters required to connect to a specific
network.  NetworkManager will _never_ activate a connection that is not in this
list, or that the user has not directed NetworkManager to connect to.


How it works:

The NetworkManager daemon runs as a privileged service (since it must access
and control hardware), but provides a D-Bus interface on the system bus to
allow for fine-grained control of networking.  NetworkManager does not store
connections or settings, it is only the mechanism by which those connections
are selected and activated.

To store pre-defined network connections, two separate services, the "system
settings service" and the "user settings service" store connection information
and provide these to NetworkManager, also via D-Bus.  Each settings service
can determine how and where it persistently stores the connection information;
for example, the GNOME applet stores its configuration in GConf, and the system
settings service stores its config in distro-specific formats, or in a distro-
agnostic format, depending on user/administrator preference.

A variety of other system services are used by NetworkManager to provide
network functionality: wpa_supplicant for wireless connections and 802.1x
wired connections, pppd for PPP and mobile broadband connections, DHCP clients
for dynamic IP addressing, dnsmasq for proxy nameserver and DHCP server
functionality for internet connection sharing, and avahi-autoipd for IPv4
link-local addresses.  Most communication with these daemons occurs, again,
via D-Bus.


Why doesn't my network Just Work?

Driver problems are the #1 cause of why NetworkManager sometimes fails to
connect to wireless networks.  Often, the driver simply doesn't behave in a
consistent manner, or is just plain buggy.  NetworkManager supports _only_
those drivers that are shipped with the upstream Linux kernel, because only
those drivers can be easily fixed and debugged.  ndiswrapper, vendor binary
drivers, or other out-of-tree drivers may or may not work well with
NetworkManager, precisely because they have not been vetted and improved by the
open-source community, and because problems in these drivers usually cannot
be fixed.

Sometimes, command-line tools like 'iwconfig' will work, but NetworkManager will
fail.  This is again often due to buggy drivers, because these drivers simply
aren't expecting the dynamic requests that NetworkManager and wpa_supplicant
make.  Driver bugs should be filed in the bug tracker of the distribution being
run, since often distributions customize their kernel and drivers.

Sometimes, it really is NetworkManager's fault.  If you think that's
the case, please file a bug at:

https://gitlab.freedesktop.org/NetworkManager/NetworkManager/issues

Attaching NetworkManager debug logs from the journal (or wherever your
distribution directs syslog's 'daemon' facility output, as
/var/log/messages or /var/log/daemon.log) is often very helpful, and
(if you can get) a working wpa_supplicant config file helps
enormously.  See the logging section of file
contrib/fedora/rpm/NetworkManager.conf for how to enable debug logging
in NetworkManager.
