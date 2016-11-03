# SPEC file to build NetworkManager for testing. It aims for a similar
# configuration as rhel-7.0 and Fedora rawhide
#
# This spec file is not used as is to create official packages for RHEL, Fedora or any
# other distribution.
#
# Note that it contains __PLACEHOLDERS__ that will be replaced by the accompanying 'build.sh' script.


%global dbus_version 1.1
%global dbus_glib_version 0.100

%global wireless_tools_version 1:28-0pre9
%global libnl3_version 3.2.7

%global ppp_version %(sed -n 's/^#define\\s*VERSION\\s*"\\([^\\s]*\\)"$/\\1/p' %{_includedir}/pppd/patchlevel.h 2>/dev/null | grep . || echo bad)
%global glib2_version %(pkg-config --modversion glib-2.0 2>/dev/null || echo bad)

%global snapshot %{nil}
%global git_sha __COMMIT__

%global rpm_version __VERSION__
%global real_version __VERSION__
%global release_version __RELEASE_VERSION__
%global epoch_version 1

%global obsoletes_device_plugins 1:0.9.9.95-1
%global obsoletes_dhclient 1:1.5.0

%global systemd_dir %{_prefix}/lib/systemd/system
%global nmlibdir %{_prefix}/lib/%{name}

%global _hardened_build 1

%if x%{?snapshot} != x
%global snapshot_dot .%{snapshot}
%endif
%if x%{?git_sha} != x
%global git_sha_dot .%{git_sha}
%endif

%global snap %{?snapshot_dot}%{?git_sha_dot}

###############################################################################

%bcond_without adsl

%global default_with_bluetooth 1
%global default_with_wwan 1

# ModemManager on Fedora < 20 too old for Bluetooth && wwan
%if (0%{?fedora} && 0%{?fedora} < 20)
%global default_with_bluetooth 0
%global default_with_wwan 0
%endif

# Bluetooth requires the WWAN plugin
%if 0%{?default_with_bluetooth}
%global default_with_wwan 1
%endif

%if 0%{?default_with_bluetooth}
%bcond_without bluetooth
%else
%bcond_with bluetooth
%endif

%if 0%{?default_with_wwan}
%bcond_without wwan
%else
%bcond_with wwan
%endif

%if (0%{?fedora} && 0%{?fedora} <= 19)
%bcond_with team
%else
%bcond_without team
%endif

%bcond_without wifi

%bcond_without nmtui
%bcond_without regen_docs
%bcond_with    debug
%bcond_without test

###############################################################################

%if %{with bluetooth} || (%{with wwan} && (0%{?rhel} || (0%{?fedora} && 0%{?fedora} > 19)))
%global with_modem_manager_1 1
%else
%global with_modem_manager_1 0
%endif

###############################################################################

Name: NetworkManager
Summary: Network connection manager and user applications
Epoch: %{epoch_version}
Version: %{rpm_version}
Release: %{release_version}%{?snap}%{?dist}
Group: System Environment/Base
License: GPLv2+
URL: http://www.gnome.org/projects/NetworkManager/

Source: __SOURCE1__
Source1: NetworkManager.conf
Source2: 00-server.conf
Source3: 20-connectivity-fedora.conf
Source4: 05-dhcp-dhclient.conf

#Patch1: 0001-some.patch

Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

Requires: dbus >= %{dbus_version}
Requires: glib2 >= %{glib2_version}
Requires: libnl3 >= %{libnl3_version}
Requires: %{name}-libnm%{?_isa} = %{epoch}:%{version}-%{release}
Requires: ppp = %{ppp_version}
Obsoletes: dhcdbd
Obsoletes: NetworkManager < %{obsoletes_device_plugins}
Obsoletes: NetworkManager-wimax < 1.2

Conflicts: NetworkManager-vpnc < 1:0.7.0.99-1
Conflicts: NetworkManager-openvpn < 1:0.7.0.99-1
Conflicts: NetworkManager-pptp < 1:0.7.0.99-1
Conflicts: NetworkManager-openconnect < 0:0.7.0.99-1
Conflicts: kde-plasma-networkmanagement < 1:0.9-0.49.20110527git.nm09

BuildRequires: dbus-devel >= %{dbus_version}
BuildRequires: dbus-glib-devel >= %{dbus_glib_version}
%if 0%{?fedora}
BuildRequires: wireless-tools-devel >= %{wireless_tools_version}
%endif
BuildRequires: glib2-devel >= 2.32.0
BuildRequires: gobject-introspection-devel >= 0.10.3
BuildRequires: gettext-devel
BuildRequires: pkgconfig
BuildRequires: libnl3-devel >= %{libnl3_version}
BuildRequires: perl(XML::Parser)
BuildRequires: perl(YAML)
BuildRequires: automake autoconf intltool libtool
BuildRequires: ppp-devel >= 2.4.5
BuildRequires: nss-devel >= 3.11.7
BuildRequires: dhclient
BuildRequires: readline-devel
BuildRequires: audit-libs-devel
%if %{with regen_docs}
BuildRequires: gtk-doc
%endif
BuildRequires: libudev-devel
BuildRequires: libuuid-devel
BuildRequires: libgudev1-devel >= 143
BuildRequires: vala-tools
BuildRequires: iptables
%if %{with bluetooth}
BuildRequires: bluez-libs-devel
%endif
BuildRequires: systemd >= 200-3 systemd-devel
BuildRequires: libsoup-devel
BuildRequires: libndp-devel >= 1.0
%if 0%{?with_modem_manager_1}
BuildRequires: ModemManager-glib-devel >= 1.0
%endif
%if %{with nmtui}
BuildRequires: newt-devel
%endif
BuildRequires: /usr/bin/dbus-launch
BuildRequires: pygobject3-base
BuildRequires: dbus-python
BuildRequires: libselinux-devel
BuildRequires: polkit-devel
BuildRequires: jansson-devel


%description
NetworkManager is a system service that manages network interfaces and
connections based on user or automatic configuration. It supports
Ethernet, Bridge, Bond, VLAN, Team, InfiniBand, Wi-Fi, mobile broadband
(WWAN), PPPoE and other devices, and supports a variety of different VPN
services.


%if %{with adsl}
%package adsl
Summary: ADSL device plugin for NetworkManager
Group: System Environment/Base
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}
Obsoletes: NetworkManager < %{obsoletes_device_plugins}
Obsoletes: NetworkManager-atm

%description adsl
This package contains NetworkManager support for ADSL devices.
%endif


%if %{with bluetooth}
%package bluetooth
Summary: Bluetooth device plugin for NetworkManager
Group: System Environment/Base
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}
Requires: NetworkManager-wwan = %{epoch}:%{version}-%{release}
Requires: bluez >= 4.101-5
Obsoletes: NetworkManager < %{obsoletes_device_plugins}
Obsoletes: NetworkManager-bt

%description bluetooth
This package contains NetworkManager support for Bluetooth devices.
%endif


%if %{with team}
%package team
Summary: Team device plugin for NetworkManager
Group: System Environment/Base
BuildRequires: teamd-devel
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}
Obsoletes: NetworkManager < %{obsoletes_device_plugins}
# Team was split from main NM binary between 0.9.10 and 1.0
Obsoletes: NetworkManager < 1.0.0

%description team
This package contains NetworkManager support for team devices.
%endif


%if %{with wifi}
%package wifi
Summary: Wifi plugin for NetworkManager
Group: System Environment/Base
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}
Requires: wpa_supplicant >= 1:1.1
Obsoletes: NetworkManager < %{obsoletes_device_plugins}

%description wifi
This package contains NetworkManager support for Wifi and OLPC devices.
%endif


%if %{with wwan}
%package wwan
Summary: Mobile broadband device plugin for NetworkManager
Group: System Environment/Base
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}
Requires: ModemManager
Obsoletes: NetworkManager < %{obsoletes_device_plugins}

%description wwan
This package contains NetworkManager support for mobile broadband (WWAN)
devices.
%endif


%package glib
Summary: Libraries for adding NetworkManager support to applications (old API).
Group: Development/Libraries
Requires: dbus >= %{dbus_version}
Requires: dbus-glib >= %{dbus_glib_version}

%description glib
This package contains the libraries that make it easier to use some
NetworkManager functionality from applications that use glib.  This is
the older NetworkManager API. See also NetworkManager-libnm.


%package glib-devel
Summary: Header files for adding NetworkManager support to applications (old API).
Group: Development/Libraries
Requires: %{name}-glib%{?_isa} = %{epoch}:%{version}-%{release}
Requires: glib2-devel
Requires: pkgconfig
Requires: dbus-glib-devel >= %{dbus_glib_version}
Provides: %{name}-devel = %{epoch}:%{version}-%{release}
Provides: %{name}-devel%{?_isa} = %{epoch}:%{version}-%{release}
Obsoletes: %{name}-devel < %{epoch}:%{version}-%{release}

%description glib-devel
This package contains the header and pkg-config files for development
applications using NetworkManager functionality from applications that
use glib.
This is the older NetworkManager API.  See also NetworkManager-libnm-devel.


%package libnm
Summary: Libraries for adding NetworkManager support to applications (new API).
Group: Development/Libraries

%description libnm
This package contains the libraries that make it easier to use some
NetworkManager functionality from applications.  This is the new
NetworkManager API.  See also NetworkManager-glib.


%package libnm-devel
Summary: Header files for adding NetworkManager support to applications (new API).
Group: Development/Libraries
Requires: %{name}-libnm%{?_isa} = %{epoch}:%{version}-%{release}
Requires: glib2-devel
Requires: pkgconfig

%description libnm-devel
This package contains the header and pkg-config files for development
applications using NetworkManager functionality from applications.  This
is the new NetworkManager API. See also NetworkManager-glib-devel.


%package config-connectivity-fedora
Summary: NetworkManager config file for connectivity checking via Fedora servers
Group: System Environment/Base

%description config-connectivity-fedora
This adds a NetworkManager configuration file to enable connectivity checking
via Fedora infrastructure.

%package config-server
Summary: NetworkManager config file for "server-like" defaults
Group: System Environment/Base

%description config-server
This adds a NetworkManager configuration file to make it behave more
like the old "network" service. In particular, it stops NetworkManager
from automatically running DHCP on unconfigured ethernet devices, and
allows connections with static IP addresses to be brought up even on
ethernet devices with no carrier.

This package is intended to be installed by default for server
deployments.

%package config-dhcp-dhclient
Summary: NetworkManager config file to use dhclient as DHCP plugin
Group: System Environment/Base
BuildArch: noarch
Requires: dhclient >= 12:4.1.0
Provides: %{name}%{?_isa} = %{epoch}:%{version}-%{release}
Obsoletes: %{name} < %{obsoletes_dhclient}

%description config-dhcp-dhclient
This adds a NetworkManager configuration file to configure dhclient
as DHCP plugin.

%package dispatcher-routing-rules
Summary: NetworkManager dispatcher file for advanced routing rules
Group: System Environment/Base
BuildArch: noarch
Provides: %{name}-config-routing-rules = %{epoch}:%{version}-%{release}
Obsoletes: %{name}-config-routing-rules < %{epoch}:%{version}-%{release}

%description dispatcher-routing-rules
This adds a NetworkManager dispatcher file to support networking
configurations using "/etc/sysconfig/network-scripts/rule-NAME" files
(eg, to do policy-based routing).

%if 0%{with_nmtui}
%package tui
Summary: NetworkManager curses-based UI
Group: System Environment/Base
Requires: %{name} = %{epoch}:%{version}-%{release}
Requires: %{name}-libnm%{?_isa} = %{epoch}:%{version}-%{release}

%description tui
This adds a curses-based "TUI" (Text User Interface) to
NetworkManager, to allow performing some of the operations supported
by nm-connection-editor and nm-applet in a non-graphical environment.
%endif

%prep
%setup -q -n NetworkManager-%{real_version}

#%patch1 -p1

%build
%if %{with regen_docs}
gtkdocize
%endif
autoreconf --install --force
intltoolize --automake --copy --force
%configure \
	--disable-static \
	--with-dhclient=yes \
	--with-dhcpcd=no \
	--with-crypto=nss \
	--enable-more-warnings=error \
%if %{with debug}
	--with-more-logging \
	--with-more-asserts=10000 \
%endif
	--enable-ld-gc \
	--enable-ppp=yes \
	--with-libaudit=yes-disabled-by-default \
%if 0%{?with_modem_manager_1}
	--with-modem-manager-1=yes \
%else
	--with-modem-manager-1=no \
%endif
%if %{with wifi}
	--enable-wifi=yes \
%if 0%{?fedora}
	--with-wext=yes \
%else
	--with-wext=no \
%endif
%else
	--enable-wifi=no \
%endif
	--enable-vala=yes \
%if %{with regen_docs}
	--enable-gtk-doc \
%else
	--disable-gtk-doc \
%endif
%if %{with team}
	--enable-teamdctl=yes \
%else
	--enable-teamdctl=no \
%endif
	--with-selinux=yes \
	--enable-polkit=yes \
	--enable-polkit-agent \
	--enable-modify-system=yes \
	--enable-concheck \
	--with-session-tracking=systemd \
	--with-suspend-resume=systemd \
	--with-systemdsystemunitdir=%{systemd_dir} \
	--with-system-ca-path=/etc/pki/tls/cert.pem \
	--with-tests=yes \
	--with-valgrind=no \
	--enable-ifcfg-rh=yes \
	--with-system-libndp=yes \
	--with-pppd-plugin-dir=%{_libdir}/pppd/%{ppp_version} \
	--with-dist-version=%{version}-%{release} \
	--with-setting-plugins-default='ifcfg-rh,ibft' \
	--with-config-dns-rc-manager-default=symlink \
	--with-config-logging-backend-default=journal \
	--with-config-dhcp-default=internal \
	--enable-json-validation

make %{?_smp_mflags}

# regenerate src/NetworkManager.ver with the actually used
# symbols and relink.
./tools/create-exports-NetworkManager.sh update
make %{?_smp_mflags}

%install
# install NM
make install DESTDIR=%{buildroot}

cp %{SOURCE1} %{buildroot}%{_sysconfdir}/%{name}/

mkdir -p %{buildroot}%{_sysconfdir}/%{name}/conf.d
mkdir -p %{buildroot}%{nmlibdir}/conf.d
mkdir -p %{buildroot}%{nmlibdir}/VPN
cp %{SOURCE2} %{buildroot}%{nmlibdir}/conf.d/
cp %{SOURCE3} %{buildroot}%{nmlibdir}/conf.d/
cp %{SOURCE4} %{buildroot}%{nmlibdir}/conf.d/

# create a VPN directory
mkdir -p %{buildroot}%{_sysconfdir}/NetworkManager/VPN

# create a keyfile plugin system settings directory
mkdir -p %{buildroot}%{_sysconfdir}/NetworkManager/system-connections

# create a dnsmasq.d directory
mkdir -p %{buildroot}%{_sysconfdir}/NetworkManager/dnsmasq.d
mkdir -p %{buildroot}%{_sysconfdir}/NetworkManager/dnsmasq-shared.d

# create dispatcher directories
mkdir -p %{buildroot}%{_sysconfdir}/%{name}/dispatcher.d
mkdir -p %{buildroot}%{_sysconfdir}/%{name}/dispatcher.d/pre-up.d
mkdir -p %{buildroot}%{_sysconfdir}/%{name}/dispatcher.d/pre-down.d
mkdir -p %{buildroot}%{_sysconfdir}/%{name}/dispatcher.d/no-wait.d
cp examples/dispatcher/10-ifcfg-rh-routes.sh %{buildroot}%{_sysconfdir}/%{name}/dispatcher.d/
ln -s ../no-wait.d/10-ifcfg-rh-routes.sh %{buildroot}%{_sysconfdir}/%{name}/dispatcher.d/pre-up.d/
ln -s ../10-ifcfg-rh-routes.sh %{buildroot}%{_sysconfdir}/%{name}/dispatcher.d/no-wait.d/

mkdir -p %{buildroot}%{_datadir}/gnome-vpn-properties

mkdir -p %{buildroot}%{_localstatedir}/lib/NetworkManager

%find_lang %{name}

rm -f %{buildroot}%{_libdir}/*.la
rm -f %{buildroot}%{_libdir}/pppd/%{ppp_version}/*.la
rm -f %{buildroot}%{_libdir}/NetworkManager/*.la

# Ensure the documentation timestamps are constant to avoid multilib conflicts
find %{buildroot}%{_datadir}/gtk-doc -exec touch --reference configure.ac '{}' \+

%if 0%{?__debug_package}
mkdir -p %{buildroot}%{_prefix}/src/debug/NetworkManager-%{real_version}
cp valgrind.suppressions %{buildroot}%{_prefix}/src/debug/NetworkManager-%{real_version}
%endif


%check
%if %{with test}
make %{?_smp_mflags} check
%endif


%post
/usr/bin/udevadm control --reload-rules || :
/usr/bin/udevadm trigger --subsystem-match=net || :

%systemd_post NetworkManager.service NetworkManager-wait-online.service NetworkManager-dispatcher.service

%preun
if [ $1 -eq 0 ]; then
    # Package removal, not upgrade
    /bin/systemctl --no-reload disable NetworkManager.service >/dev/null 2>&1 || :

    # Don't kill networking entirely just on package remove
    #/bin/systemctl stop NetworkManager.service >/dev/null 2>&1 || :
fi
%systemd_preun NetworkManager-wait-online.service NetworkManager-dispatcher.service

%postun
/usr/bin/udevadm control --reload-rules || :
/usr/bin/udevadm trigger --subsystem-match=net || :

%systemd_postun


%post	glib -p /sbin/ldconfig
%postun	glib -p /sbin/ldconfig

%post	libnm -p /sbin/ldconfig
%postun	libnm -p /sbin/ldconfig


%files -f %{name}.lang
%{_sysconfdir}/dbus-1/system.d/org.freedesktop.NetworkManager.conf
%{_sysconfdir}/dbus-1/system.d/nm-dispatcher.conf
%{_sysconfdir}/dbus-1/system.d/nm-ifcfg-rh.conf
%{_sbindir}/%{name}
%{_bindir}/nmcli
%{_datadir}/bash-completion/completions/nmcli
%dir %{_sysconfdir}/%{name}/
%dir %{_sysconfdir}/%{name}/dispatcher.d
%dir %{_sysconfdir}/%{name}/dispatcher.d/pre-down.d
%dir %{_sysconfdir}/%{name}/dispatcher.d/pre-up.d
%dir %{_sysconfdir}/%{name}/dispatcher.d/no-wait.d
%dir %{_sysconfdir}/%{name}/dnsmasq.d
%dir %{_sysconfdir}/%{name}/dnsmasq-shared.d
%dir %{_sysconfdir}/%{name}/VPN
%config(noreplace) %{_sysconfdir}/%{name}/NetworkManager.conf
%{_bindir}/nm-online
%{_libexecdir}/nm-dhcp-helper
%{_libexecdir}/nm-dispatcher
%{_libexecdir}/nm-iface-helper
%dir %{_libdir}/NetworkManager
%{_libdir}/NetworkManager/libnm-settings-plugin*.so
%if %{with nmtui}
%exclude %{_mandir}/man1/nmtui*
%endif
%dir %{_sysconfdir}/%{name}
%dir %{_sysconfdir}/%{name}/conf.d
%dir %{nmlibdir}
%dir %{nmlibdir}/conf.d
%dir %{nmlibdir}/VPN
%{_mandir}/man1/*
%{_mandir}/man5/*
%{_mandir}/man7/*
%{_mandir}/man8/*
%dir %{_localstatedir}/lib/NetworkManager
%dir %{_sysconfdir}/NetworkManager/system-connections
%{_datadir}/dbus-1/system-services/org.freedesktop.NetworkManager.service
%{_datadir}/dbus-1/system-services/org.freedesktop.nm_dispatcher.service
%{_libdir}/pppd/%{ppp_version}/nm-pppd-plugin.so
%{_datadir}/polkit-1/actions/*.policy
%{_prefix}/lib/udev/rules.d/*.rules
# systemd stuff
%{systemd_dir}/NetworkManager.service
%{systemd_dir}/NetworkManager-wait-online.service
%{systemd_dir}/NetworkManager-dispatcher.service
%{systemd_dir}/network-online.target.wants/NetworkManager-wait-online.service
%dir %{_datadir}/doc/NetworkManager/examples
%{_datadir}/doc/NetworkManager/examples/server.conf
%doc NEWS AUTHORS README CONTRIBUTING TODO
%license COPYING

%if %{with adsl}
%files adsl
%{_libdir}/%{name}/libnm-device-plugin-adsl.so
%else
%exclude %{_libdir}/%{name}/libnm-device-plugin-adsl.so
%endif

%if %{with bluetooth}
%files bluetooth
%{_libdir}/%{name}/libnm-device-plugin-bluetooth.so
%endif

%if %{with team}
%files team
%{_libdir}/%{name}/libnm-device-plugin-team.so
%endif

%if %{with wifi}
%files wifi
%{_libdir}/%{name}/libnm-device-plugin-wifi.so
%endif

%if %{with wwan}
%files wwan
%{_libdir}/%{name}/libnm-device-plugin-wwan.so
%{_libdir}/%{name}/libnm-wwan.so
%endif

%files glib
%{_libdir}/libnm-glib.so.*
%{_libdir}/libnm-glib-vpn.so.*
%{_libdir}/libnm-util.so.*
%{_libdir}/girepository-1.0/NetworkManager-1.0.typelib
%{_libdir}/girepository-1.0/NMClient-1.0.typelib

%files glib-devel
%doc ChangeLog docs/api/html/*
%dir %{_includedir}/libnm-glib
%dir %{_includedir}/%{name}
%{_includedir}/libnm-glib/*.h
%{_includedir}/%{name}/%{name}.h
%{_includedir}/%{name}/NetworkManagerVPN.h
%{_includedir}/%{name}/nm-setting*.h
%{_includedir}/%{name}/nm-connection.h
%{_includedir}/%{name}/nm-utils-enum-types.h
%{_includedir}/%{name}/nm-utils.h
%{_includedir}/%{name}/nm-version.h
%{_includedir}/%{name}/nm-version-macros.h
%{_libdir}/pkgconfig/libnm-glib.pc
%{_libdir}/pkgconfig/libnm-glib-vpn.pc
%{_libdir}/pkgconfig/libnm-util.pc
%{_libdir}/pkgconfig/%{name}.pc
%{_libdir}/libnm-glib.so
%{_libdir}/libnm-glib-vpn.so
%{_libdir}/libnm-util.so
%{_datadir}/gir-1.0/NetworkManager-1.0.gir
%{_datadir}/gir-1.0/NMClient-1.0.gir
%dir %{_datadir}/gtk-doc/html/libnm-glib
%{_datadir}/gtk-doc/html/libnm-glib/*
%dir %{_datadir}/gtk-doc/html/libnm-util
%{_datadir}/gtk-doc/html/libnm-util/*
%dir %{_datadir}/gtk-doc/html/NetworkManager
%{_datadir}/gtk-doc/html/NetworkManager/*
%{_datadir}/vala/vapi/libnm-*.deps
%{_datadir}/vala/vapi/libnm-*.vapi

%files libnm
%{_libdir}/libnm.so.*
%{_libdir}/girepository-1.0/NM-1.0.typelib

%files libnm-devel
%doc ChangeLog docs/api/html/*
%dir %{_includedir}/libnm
%{_includedir}/libnm/*.h
%{_libdir}/pkgconfig/libnm.pc
%{_libdir}/libnm.so
%{_datadir}/gir-1.0/NM-1.0.gir
%dir %{_datadir}/gtk-doc/html/libnm
%{_datadir}/gtk-doc/html/libnm/*
%{_datadir}/vala/vapi/libnm.deps
%{_datadir}/vala/vapi/libnm.vapi

%files config-connectivity-fedora
%dir %{nmlibdir}
%dir %{nmlibdir}/conf.d
%{nmlibdir}/conf.d/20-connectivity-fedora.conf

%files config-server
%dir %{nmlibdir}
%dir %{nmlibdir}/conf.d
%{nmlibdir}/conf.d/00-server.conf

%files config-dhcp-dhclient
%dir %{nmlibdir}
%dir %{nmlibdir}/conf.d
%{nmlibdir}/conf.d/05-dhcp-dhclient.conf

%files dispatcher-routing-rules
%{_sysconfdir}/%{name}/dispatcher.d/10-ifcfg-rh-routes.sh
%{_sysconfdir}/%{name}/dispatcher.d/no-wait.d/10-ifcfg-rh-routes.sh
%{_sysconfdir}/%{name}/dispatcher.d/pre-up.d/10-ifcfg-rh-routes.sh

%if %{with nmtui}
%files tui
%{_bindir}/nmtui
%{_bindir}/nmtui-edit
%{_bindir}/nmtui-connect
%{_bindir}/nmtui-hostname
%{_mandir}/man1/nmtui*
%endif

%changelog
__CHANGELOG__

