# SPEC file to build NetworkManager for testing. It aims for a similar
# configuration as rhel-7.0 and Fedora rawhide
#
# This spec file is not used as is to create official packages for RHEL, Fedora or any
# other distribution.
#
# Note that it contains __PLACEHOLDERS__ that will be replaced by the accompanying 'build.sh' script.


%define dbus_version 1.1
%define dbus_glib_version 0.100

%define glib2_version	2.32.0
%define wireless_tools_version 1:28-0pre9
%define libnl3_version 3.2.7

%define ppp_version %(rpm -q ppp-devel >/dev/null && rpm -q --qf '%%{version}' ppp-devel || echo -n bad)

%define snapshot %{nil}
%define git_sha __COMMIT__
%define realversion __VERSION__
%define release_version __RELEASE_VERSION__
%define epoch_version 1

%define obsoletes_nmver 1:0.9.9.95-1

%global with_nmtui 1

%if 0%{?fedora}
%global regen_docs 1
%else
%global regen_docs 1
%endif

%define systemd_dir %{_prefix}/lib/systemd/system
%define udev_dir %{_prefix}/lib/udev
%define nmlibdir %{_prefix}/lib/%{name}

%global with_adsl 1
%global with_bluetooth 1
%global with_team 1
%global with_wifi 1
%global with_wimax 0
%global with_wwan 1

# WiMAX still supported on <= F19
%if ! 0%{?rhel} && (! 0%{?fedora} || 0%{?fedora} < 20)
%global with_wimax 1
%endif

# ModemManager on Fedora < 20 too old for Bluetooth && wwan
%if (0%{?fedora} && 0%{?fedora} < 20)
%global with_bluetooth 0
%global with_wwan 0
%endif

# Bluetooth requires the WWAN plugin
%if 0%{?with_bluetooth}
%global with_wwan 1
%endif

%if (0%{?fedora} && 0%{?fedora} <= 19)
%global with_team 0
%endif

%define with_modem_manager_1 0
%if 0%{?with_bluetooth} || (0%{?with_wwan} && (0%{?rhel} || (0%{?fedora} && 0%{?fedora} > 19)))
%define with_modem_manager_1 1
%endif

%global _hardened_build 1

%define git_sha_version %(test -n '%{git_sha}' && echo '.%{git_sha}')

Name: NetworkManager
Summary: Network connection manager and user applications
Epoch: %{epoch_version}
Version: %{realversion}
Release: %{release_version}%{snapshot}%{git_sha_version}%{?dist}
Group: System Environment/Base
License: GPLv2+
URL: http://www.gnome.org/projects/NetworkManager/

Source: __SOURCE1__
Source1: NetworkManager.conf
Source2: 00-server.conf
Source3: 20-connectivity-fedora.conf

#Patch1: 0001-some.patch

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%if 0%{?fedora} && 0%{?fedora} < 20
Requires(post): chkconfig
Requires(preun): chkconfig
%endif
Requires(post): systemd-sysv
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

Requires: dbus >= %{dbus_version}
Requires: dbus-glib >= %{dbus_glib_version}
Requires: glib2 >= %{glib2_version}
Requires: iproute
Requires: dhclient >= 12:4.1.0
Requires: libnl3 >= %{libnl3_version}
Requires: %{name}-libnm%{?_isa} = %{epoch}:%{version}-%{release}
Requires: ppp = %{ppp_version}
Requires: dnsmasq
Requires: udev
Requires: iptables
Requires: readline
Obsoletes: dhcdbd
Obsoletes: NetworkManager < %{obsoletes_nmver}

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
BuildRequires: glib2-devel >= %{glib2_version}
BuildRequires: gobject-introspection-devel >= 0.10.3
BuildRequires: gettext-devel
BuildRequires: /usr/bin/autopoint
BuildRequires: pkgconfig
BuildRequires: libnl3-devel >= %{libnl3_version}
BuildRequires: perl(XML::Parser)
BuildRequires: perl(YAML)
BuildRequires: automake autoconf intltool libtool
BuildRequires: ppp-devel >= 2.4.5
BuildRequires: nss-devel >= 3.11.7
BuildRequires: dhclient
BuildRequires: readline-devel
%if %{regen_docs}
BuildRequires: gtk-doc
%endif
BuildRequires: libudev-devel
BuildRequires: libuuid-devel
BuildRequires: libgudev1-devel >= 143
BuildRequires: vala-tools
BuildRequires: iptables
%if 0%{?with_bluetooth}
BuildRequires: bluez-libs-devel
%endif
%if 0%{?with_wimax}
BuildRequires: wimax-devel
%endif
BuildRequires: systemd >= 200-3 systemd-devel
BuildRequires: libsoup-devel
BuildRequires: libndp-devel >= 1.0
%if 0%{?with_modem_manager_1}
BuildRequires: ModemManager-glib-devel >= 1.0
%endif
%if 0%{?with_nmtui}
BuildRequires: newt-devel
%endif
BuildRequires: /usr/bin/dbus-launch
BuildRequires: pygobject3-base
BuildRequires: dbus-python
BuildRequires: libselinux-devel
BuildRequires: polkit-devel


%description
NetworkManager is a system service that manages network interfaces and
connections based on user or automatic configuration. It supports
Ethernet, Bridge, Bond, VLAN, Team, InfiniBand, Wi-Fi, mobile broadband
(WWAN), PPPoE and other devices, and supports a variety of different VPN
services.


%if 0%{?with_adsl}
%package adsl
Summary: ADSL device plugin for NetworkManager
Group: System Environment/Base
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}
Obsoletes: NetworkManager < %{obsoletes_nmver}
Obsoletes: NetworkManager-atm

%description adsl
This package contains NetworkManager support for ADSL devices.
%endif


%if 0%{?with_bluetooth}
%package bluetooth
Summary: Bluetooth device plugin for NetworkManager
Group: System Environment/Base
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}
Requires: NetworkManager-wwan
Requires: bluez >= 4.101-5
Obsoletes: NetworkManager < %{obsoletes_nmver}
Obsoletes: NetworkManager-bt

%description bluetooth
This package contains NetworkManager support for Bluetooth devices.
%endif


%if 0%{?with_team}
%package team
Summary: Team device plugin for NetworkManager
Group: System Environment/Base
BuildRequires: teamd-devel
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}
Obsoletes: NetworkManager < %{obsoletes_nmver}
# Team was split from main NM binary between 0.9.10 and 1.0
Obsoletes: NetworkManager < 1.0.0

%description team
This package contains NetworkManager support for team devices.
%endif


%if 0%{?with_wifi}
%package wifi
Summary: Wifi plugin for NetworkManager
Group: System Environment/Base
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}
Requires: wpa_supplicant >= 1:1.1
Obsoletes: NetworkManager < %{obsoletes_nmver}

%description wifi
This package contains NetworkManager support for Wifi and OLPC devices.
%endif


%if 0%{?with_wwan}
%package wwan
Summary: Mobile broadband device plugin for NetworkManager
Group: System Environment/Base
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}
Requires: ModemManager
Obsoletes: NetworkManager < %{obsoletes_nmver}

%description wwan
This package contains NetworkManager support for mobile broadband (WWAN) devices.
%endif


%if 0%{?with_wimax}
%package wimax
Summary: Intel WiMAX device support for NetworkManager
Group: System Environment/Base
Requires: wimax
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}

%description wimax
This package contains NetworkManager support for Intel WiMAX mobile broadband
devices.
%endif


%package devel
Summary: Headers defining the NetworkManager D-Bus APIs
Group: Development/Libraries
Requires: %{name} = %{epoch}:%{version}-%{release}
Requires: dbus-devel >= %{dbus_version}
Requires: dbus-glib >= %{dbus_glib_version}
Requires: pkgconfig

%description devel
This package contains various headers accessing some NetworkManager functionality
from applications.


%package glib
Summary: Libraries for adding NetworkManager support to applications (old API).
Group: Development/Libraries
Requires: dbus >= %{dbus_version}
Requires: dbus-glib >= %{dbus_glib_version}

%description glib
This package contains the libraries that make it easier to use some NetworkManager
functionality from applications that use glib.  This is the older NetworkManager API.
See also NetworkManager-libnm.


%package glib-devel
Summary: Header files for adding NetworkManager support to applications (old API).
Group: Development/Libraries
Requires: %{name}-devel%{?_isa} = %{epoch}:%{version}-%{release}
Requires: %{name}-glib%{?_isa} = %{epoch}:%{version}-%{release}
Requires: glib2-devel
Requires: pkgconfig
Requires: dbus-glib-devel >= %{dbus_glib_version}

%description glib-devel
This package contains the header and pkg-config files for development applications using
NetworkManager functionality from applications that use glib.  This is the older
NetworkManager API. See also NetworkManager-libnm-devel.


%package libnm
Summary: Libraries for adding NetworkManager support to applications (new API).
Group: Development/Libraries

%description libnm
This package contains the libraries that make it easier to use some NetworkManager
functionality from applications.  This is the new NetworkManager API.  See also
NetworkManager-glib.


%package libnm-devel
Summary: Header files for adding NetworkManager support to applications (new API).
Group: Development/Libraries
Requires: %{name}-devel%{?_isa} = %{epoch}:%{version}-%{release}
Requires: %{name}-libnm%{?_isa} = %{epoch}:%{version}-%{release}
Requires: glib2-devel
Requires: pkgconfig

%description libnm-devel
This package contains the header and pkg-config files for development applications using
NetworkManager functionality from applications.  This is the new NetworkManager API.
See also NetworkManager-glib-devel.


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
%setup -q -n NetworkManager-%{realversion}

#%patch1 -p1 -b .0001-some.orig

%build

%if %{regen_docs}
# back up pristine docs and use them instead of generated ones, which make
# multilib unhappy due to different timestamps in the generated content
%{__cp} -R docs ORIG-docs
%endif

#autopoint --force
#intltoolize --force
%configure \
	--disable-static \
	--with-dhclient=yes \
	--with-dhcpcd=no \
	--with-crypto=nss \
	--enable-more-warnings=error \
	--enable-ppp=yes \
%if 0%{?with_modem_manager_1}
	--with-modem-manager-1=yes \
%else
	--with-modem-manager-1=no \
%endif
%if 0%{?with_wifi}
	--enable-wifi=yes \
%if 0%{?fedora}
	--with-wext=yes \
%else
	--with-wext=no \
%endif
%else
	--enable-wifi=no \
%endif
%if 0%{?with_wimax}
	--enable-wimax=yes \
%else
	--enable-wimax=no \
%endif
	--enable-vala=yes \
%if 0%{?regen_docs}
	--enable-gtk-doc \
%else
	--disable-gtk-doc \
%endif
%if 0%{?with_team}
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
	--with-udev-dir=%{udev_dir} \
	--with-system-ca-path=/etc/pki/tls/cert.pem \
	--with-tests=yes \
	--with-valgrind=no \
	--enable-ifcfg-rh=yes \
	--with-system-libndp=yes \
	--with-pppd-plugin-dir=%{_libdir}/pppd/%{ppp_version} \
	--with-dist-version=%{version}-%{release} \
	--with-setting-plugins-default='ifcfg-rh,ibft'

make %{?_smp_mflags}

%install
%{__rm} -rf $RPM_BUILD_ROOT

# install NM
make install DESTDIR=$RPM_BUILD_ROOT

%{__cp} %{SOURCE1} $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/conf.d
mkdir -p $RPM_BUILD_ROOT%{nmlibdir}/conf.d
mkdir -p $RPM_BUILD_ROOT%{nmlibdir}/VPN
%{__cp} %{SOURCE2} $RPM_BUILD_ROOT%{nmlibdir}/conf.d/
%{__cp} %{SOURCE3} $RPM_BUILD_ROOT%{nmlibdir}/conf.d/

# create a VPN directory
%{__mkdir_p} $RPM_BUILD_ROOT%{_sysconfdir}/NetworkManager/VPN

# create a keyfile plugin system settings directory
%{__mkdir_p} $RPM_BUILD_ROOT%{_sysconfdir}/NetworkManager/system-connections

# create a dnsmasq.d directory
%{__mkdir_p} $RPM_BUILD_ROOT%{_sysconfdir}/NetworkManager/dnsmasq.d

# create dispatcher directories
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/dispatcher.d
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/dispatcher.d/pre-up.d
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/dispatcher.d/pre-down.d
%{__cp} examples/dispatcher/10-ifcfg-rh-routes.sh $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/dispatcher.d/
%{__ln_s} ../10-ifcfg-rh-routes.sh $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/dispatcher.d/pre-up.d/

%{__mkdir_p} $RPM_BUILD_ROOT%{_datadir}/gnome-vpn-properties

%{__mkdir_p} $RPM_BUILD_ROOT%{_localstatedir}/lib/NetworkManager

%find_lang %{name}

%{__rm} -f $RPM_BUILD_ROOT%{_libdir}/*.la
%{__rm} -f $RPM_BUILD_ROOT%{_libdir}/pppd/%{ppp_version}/*.la
%{__rm} -f $RPM_BUILD_ROOT%{_libdir}/NetworkManager/*.la

%if %{regen_docs}
# install the pristine docs
%{__cp} ORIG-docs/libnm-glib/html/* $RPM_BUILD_ROOT%{_datadir}/gtk-doc/html/libnm-glib/
%{__cp} ORIG-docs/libnm-util/html/* $RPM_BUILD_ROOT%{_datadir}/gtk-doc/html/libnm-util/
%endif

%clean
%{__rm} -rf $RPM_BUILD_ROOT


%check
make check


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


%files -f %{name}.lang
%defattr(-,root,root,0755)
%doc COPYING NEWS AUTHORS README CONTRIBUTING TODO
%{_sysconfdir}/dbus-1/system.d/org.freedesktop.NetworkManager.conf
%{_sysconfdir}/dbus-1/system.d/nm-dispatcher.conf
%{_sysconfdir}/dbus-1/system.d/nm-ifcfg-rh.conf
%{_sbindir}/%{name}
%{_bindir}/nmcli
%{_datadir}/bash-completion/completions/nmcli
%dir %{_sysconfdir}/%{name}/
%dir %{_sysconfdir}/%{name}/dispatcher.d
%{_sysconfdir}/%{name}/dispatcher.d/10-ifcfg-rh-routes.sh
%dir %{_sysconfdir}/%{name}/dispatcher.d/pre-down.d
%dir %{_sysconfdir}/%{name}/dispatcher.d/pre-up.d
%{_sysconfdir}/%{name}/dispatcher.d/pre-up.d/10-ifcfg-rh-routes.sh
%dir %{_sysconfdir}/%{name}/dnsmasq.d
%dir %{_sysconfdir}/%{name}/VPN
%config(noreplace) %{_sysconfdir}/%{name}/NetworkManager.conf
%{_bindir}/nm-online
%{_libexecdir}/nm-dhcp-helper
%{_libexecdir}/nm-dispatcher
%{_libexecdir}/nm-iface-helper
%dir %{_libdir}/NetworkManager
%{_libdir}/NetworkManager/libnm-settings-plugin*.so
%if 0%{?with_nmtui}
%exclude %{_mandir}/man1/nmtui*
%endif
%dir %{_sysconfdir}/%{name}
%dir %{_sysconfdir}/%{name}/conf.d
%dir %{nmlibdir}
%dir %{nmlibdir}/conf.d
%dir %{nmlibdir}/VPN
%{_mandir}/man1/*
%{_mandir}/man5/*
%{_mandir}/man8/*
%dir %{_localstatedir}/lib/NetworkManager
%dir %{_sysconfdir}/NetworkManager/system-connections
%{_datadir}/dbus-1/system-services/org.freedesktop.NetworkManager.service
%{_datadir}/dbus-1/system-services/org.freedesktop.nm_dispatcher.service
%{_libdir}/pppd/%{ppp_version}/nm-pppd-plugin.so
%{_datadir}/polkit-1/actions/*.policy
%{udev_dir}/rules.d/*.rules
# systemd stuff
%{systemd_dir}/NetworkManager.service
%{systemd_dir}/NetworkManager-wait-online.service
%{systemd_dir}/NetworkManager-dispatcher.service
%{systemd_dir}/network-online.target.wants/NetworkManager-wait-online.service
%dir %{_datadir}/doc/NetworkManager/examples
%{_datadir}/doc/NetworkManager/examples/server.conf

%if 0%{?with_adsl}
%files adsl
%defattr(-,root,root,0755)
%{_libdir}/%{name}/libnm-device-plugin-adsl.so
%else
%exclude %{_libdir}/%{name}/libnm-device-plugin-adsl.so
%endif

%if 0%{?with_bluetooth}
%files bluetooth
%defattr(-,root,root,0755)
%{_libdir}/%{name}/libnm-device-plugin-bluetooth.so
%endif

%if 0%{?with_team}
%files team
%defattr(-,root,root,0755)
%{_libdir}/%{name}/libnm-device-plugin-team.so
%endif

%if 0%{?with_wifi}
%files wifi
%defattr(-,root,root,0755)
%{_libdir}/%{name}/libnm-device-plugin-wifi.so
%endif

%if 0%{?with_wwan}
%files wwan
%defattr(-,root,root,0755)
%{_libdir}/%{name}/libnm-device-plugin-wwan.so
%{_libdir}/%{name}/libnm-wwan.so
%endif

%if 0%{?with_wimax}
%files wimax
%defattr(-,root,root,0755)
%{_libdir}/%{name}/libnm-device-plugin-wimax.so
%endif

%files devel
%defattr(-,root,root,0755)
%doc ChangeLog docs/api/html/*
%dir %{_includedir}/%{name}
%{_includedir}/%{name}/%{name}.h
%{_includedir}/%{name}/NetworkManagerVPN.h
%{_includedir}/%{name}/nm-version.h
%{_libdir}/pkgconfig/%{name}.pc
%dir %{_datadir}/gtk-doc/html/NetworkManager
%{_datadir}/gtk-doc/html/NetworkManager/*
%{_datadir}/vala/vapi/*.deps
%{_datadir}/vala/vapi/*.vapi

%files glib
%defattr(-,root,root,0755)
%{_libdir}/libnm-glib.so.*
%{_libdir}/libnm-glib-vpn.so.*
%{_libdir}/libnm-util.so.*
%{_libdir}/girepository-1.0/NetworkManager-1.0.typelib
%{_libdir}/girepository-1.0/NMClient-1.0.typelib

%files glib-devel
%defattr(-,root,root,0755)
%dir %{_includedir}/libnm-glib
%{_includedir}/libnm-glib/*.h
%{_includedir}/%{name}/nm-setting*.h
%{_includedir}/%{name}/nm-connection.h
%{_includedir}/%{name}/nm-utils-enum-types.h
%{_includedir}/%{name}/nm-utils.h
%{_libdir}/pkgconfig/libnm-glib.pc
%{_libdir}/pkgconfig/libnm-glib-vpn.pc
%{_libdir}/pkgconfig/libnm-util.pc
%{_libdir}/libnm-glib.so
%{_libdir}/libnm-glib-vpn.so
%{_libdir}/libnm-util.so
%{_datadir}/gir-1.0/NetworkManager-1.0.gir
%{_datadir}/gir-1.0/NMClient-1.0.gir
%dir %{_datadir}/gtk-doc/html/libnm-glib
%{_datadir}/gtk-doc/html/libnm-glib/*
%dir %{_datadir}/gtk-doc/html/libnm-util
%{_datadir}/gtk-doc/html/libnm-util/*

%files libnm
%defattr(-,root,root,0755)
%{_libdir}/libnm.so.*
%{_libdir}/girepository-1.0/NM-1.0.typelib

%files libnm-devel
%defattr(-,root,root,0755)
%dir %{_includedir}/libnm
%{_includedir}/libnm/*.h
%{_libdir}/pkgconfig/libnm.pc
%{_libdir}/libnm.so
%{_datadir}/gir-1.0/NM-1.0.gir
%dir %{_datadir}/gtk-doc/html/libnm
%{_datadir}/gtk-doc/html/libnm/*

%files config-connectivity-fedora
%defattr(-,root,root,0755)
%dir %{nmlibdir}
%dir %{nmlibdir}/conf.d
%{nmlibdir}/conf.d/20-connectivity-fedora.conf

%files config-server
%defattr(-,root,root,0755)
%dir %{nmlibdir}
%dir %{nmlibdir}/conf.d
%{nmlibdir}/conf.d/00-server.conf

%if 0%{?with_nmtui}
%files tui
%{_bindir}/nmtui
%{_bindir}/nmtui-edit
%{_bindir}/nmtui-connect
%{_bindir}/nmtui-hostname
%{_mandir}/man1/nmtui*
%endif

%changelog
__CHANGELOG__

