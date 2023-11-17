# SPEC file to build NetworkManager for testing. It aims for a similar
# configuration as rhel-7.0 and Fedora rawhide
#
# This spec file is not used as is to create official packages for RHEL, Fedora or any
# other distribution.
#
# Note that it contains __PLACEHOLDERS__ that will be replaced by the accompanying 'build.sh' script.


%global wpa_supplicant_version 1:1.1

%global ppp_version %(pkg-config --modversion pppd 2>/dev/null || sed -n 's/^#define\\s*VERSION\\s*"\\([^\\s]*\\)"$/\\1/p' %{_includedir}/pppd/patchlevel.h 2>/dev/null | grep . || echo bad)
%global glib2_version %(pkg-config --modversion glib-2.0 2>/dev/null || echo bad)

%global epoch_version 1
%global real_version __VERSION__
%global rpm_version %{real_version}
%global release_version __RELEASE_VERSION__
%global snapshot __SNAPSHOT__
%global git_sha __COMMIT__
%global bcond_default_debug __BCOND_DEFAULT_DEBUG__
%global bcond_default_lto __BCOND_DEFAULT_LTO__
%global bcond_default_test __BCOND_DEFAULT_TEST__

%global obsoletes_device_plugins     1:0.9.9.95-1
%global obsoletes_ppp_plugin         1:1.5.3
%global obsoletes_initscripts_updown 1:1.36.0-0.6
%global obsoletes_ifcfg_rh           1:1.36.2

%global nmlibdir %{_prefix}/lib/%{name}
%global nmplugindir %{_libdir}/%{name}/%{version}-%{release}

%global _hardened_build 1

%if "x%{?snapshot}" != "x"
%global snapshot_dot .%{snapshot}
%endif
%if "x%{?git_sha}" != "x"
%global git_sha_dot .%{git_sha}
%endif

%global snap %{?snapshot_dot}%{?git_sha_dot}

%global real_version_major %(printf '%s' '%{real_version}' | sed -n 's/^\\([1-9][0-9]*\\.[0-9][0-9]*\\)\\.[0-9][0-9]*$/\\1/p')

%global systemd_units NetworkManager.service NetworkManager-wait-online.service NetworkManager-dispatcher.service nm-priv-helper.service

%global systemd_units_cloud_setup nm-cloud-setup.service nm-cloud-setup.timer

###############################################################################

%bcond_with meson
%bcond_without adsl
%bcond_without bluetooth
%bcond_without wwan
%bcond_without team
%bcond_without wifi
%bcond_without ovs
%bcond_without ppp
%bcond_without nmtui
%bcond_without nm_cloud_setup
%bcond_without regen_docs
%if %{bcond_default_debug}
%bcond_without debug
%else
%bcond_with    debug
%endif
%if %{bcond_default_test}
%bcond_without test
%else
%bcond_with    test
%endif
%if "%{?bcond_default_lto}" == ""
%if 0%{?fedora} >= 33 || 0%{?rhel} >= 9
%bcond_without lto
%else
%bcond_with    lto
%endif
%else
%if %{bcond_default_lto}
%bcond_without lto
%else
%bcond_with    lto
%endif
%endif
%bcond_with    sanitizer
%if 0%{?fedora}
%bcond_without connectivity_fedora
%else
%bcond_with connectivity_fedora
%endif
%if 0%{?rhel} && 0%{?rhel} >= 8
%bcond_without connectivity_redhat
%else
%bcond_with connectivity_redhat
%endif
%if 0%{?fedora} >= 29 || 0%{?rhel} >= 8
%bcond_without crypto_gnutls
%else
%bcond_with crypto_gnutls
%endif
%if 0%{?rhel}
%bcond_with iwd
%else
%bcond_without iwd
%endif
%if 0%{?fedora} >= 32 || 0%{?rhel} >= 8
%bcond_without firewalld_zone
%else
%bcond_with firewalld_zone
%endif

###############################################################################

%if 0%{?fedora} || 0%{?rhel} >= 8
%global dbus_version 1.9.18
%global dbus_sys_dir %{_datadir}/dbus-1/system.d
%else
%global dbus_version 1.1
%global dbus_sys_dir %{_sysconfdir}/dbus-1/system.d
%endif

# Older libndp versions use select() (rh#1933041). On well known distros,
# choose a version that has the necessary fix.
%if 0%{?rhel} && 0%{?rhel} == 8
%global libndp_version 1.7-4
%else
%global libndp_version %{nil}
%endif

%if %{with bluetooth} || %{with wwan}
%global with_modem_manager_1 1
%else
%global with_modem_manager_1 0
%endif

%if 0%{?fedora} >= 31 || 0%{?rhel} >= 8
%global dhcp_default internal
%else
%global dhcp_default dhclient
%endif

%if 0%{?fedora} || 0%{?rhel} >= 8
%global logging_backend_default journal
%if 0%{?fedora} || 0%{?rhel} >= 9
%global dns_rc_manager_default auto
%else
%global dns_rc_manager_default symlink
%endif
%else
%global logging_backend_default syslog
%global dns_rc_manager_default file
%endif

%if 0%{?fedora} >= 33 || 0%{?rhel} >= 9
%global config_plugins_default_ifcfg_rh 0
%else
%global config_plugins_default_ifcfg_rh 1
%endif

%if 0%{?fedora} >= 36 || 0%{?rhel} >= 10
%global split_ifcfg_rh 1
%else
%global split_ifcfg_rh 0
%endif

%if (0%{?fedora} >= 36 && 0%{?fedora} < 39) || 0%{?rhel} >= 9
%global ifcfg_warning 1
%else
%global ifcfg_warning 0
%endif

%if 0%{?fedora} >= 39
%global ifcfg_migrate 1
%else
%global ifcfg_migrate 0
%endif

%if 0%{?fedora}
# Although eBPF would be available on Fedora's kernel, it seems
# we often get SELinux denials (rh#1651654). But even aside them,
# bpf(BPF_MAP_CREATE, ...) randomly fails with EPERM. That might
# be related to `ulimit -l`. Anyway, this is not usable at the
# moment.
%global ebpf_enabled "no"
%else
%global ebpf_enabled "no"
%endif

# Fedora 33 enables LTO by default by setting CFLAGS="-flto -ffat-lto-objects".
# However, we also require "-flto -flto-partition=none", so disable Fedora's
# default and use our configure option --with-lto instead.
%define _lto_cflags %{nil}

###############################################################################

Name: NetworkManager
Summary: Network connection manager and user applications
Epoch: %{epoch_version}
Version: %{rpm_version}
Release: %{release_version}%{?snap}%{?dist}
Group: System Environment/Base
License: GPL-2.0-or-later AND LGPL-2.1-or-later
URL: https://networkmanager.dev/

#Source: https://download.gnome.org/sources/NetworkManager/%{real_version_major}/%{name}-%{real_version}.tar.xz
Source: __SOURCE1__
Source1: NetworkManager.conf
Source2: 00-server.conf
Source4: 20-connectivity-fedora.conf
Source5: 20-connectivity-redhat.conf
Source6: 22-wifi-mac-addr.conf
Source7: 70-nm-connectivity.conf
Source8: readme-ifcfg-rh.txt
Source9: readme-ifcfg-rh-migrated.txt

#Patch1: 0001-some.patch

Requires(post): systemd
%if 0%{?fedora} || 0%{?rhel} >= 8
Requires(post): systemd-udev
%endif
Requires(post): /usr/sbin/update-alternatives
Requires(preun): systemd
Requires(preun): /usr/sbin/update-alternatives
Requires(postun): systemd

Requires: dbus >= %{dbus_version}
Requires: glib2 >= %{glib2_version}
Requires: %{name}-libnm%{?_isa} = %{epoch}:%{version}-%{release}
%if "%{libndp_version}" != ""
Requires: libndp >= %{libndp_version}
%endif
Obsoletes: NetworkManager < %{obsoletes_device_plugins}
Obsoletes: NetworkManager < %{obsoletes_ppp_plugin}
Obsoletes: NetworkManager-wimax < 1:1.2
%if 0%{?rhel} && 0%{?rhel} == 8
Suggests: NetworkManager-initscripts-updown
%endif
Obsoletes: NetworkManager < %{obsoletes_initscripts_updown}
%if 0%{?split_ifcfg_rh}
Obsoletes: NetworkManager < %{obsoletes_ifcfg_rh}
%endif

%if 0%{?rhel} && 0%{?rhel} <= 7
# Kept for RHEL to ensure that wired 802.1x works out of the box
Requires: wpa_supplicant >= 1:1.1
%endif

Conflicts: NetworkManager-vpnc < 1:0.7.0.99-1
Conflicts: NetworkManager-openvpn < 1:0.7.0.99-1
Conflicts: NetworkManager-pptp < 1:0.7.0.99-1
Conflicts: NetworkManager-openconnect < 0:0.7.0.99-1
Conflicts: kde-plasma-networkmanagement < 1:0.9-0.49.20110527git.nm09

BuildRequires: make
BuildRequires: gcc
BuildRequires: libtool
BuildRequires: pkgconfig
%if %{with meson}
BuildRequires: meson
%else
BuildRequires: automake
BuildRequires: autoconf
%endif
BuildRequires: gettext-devel >= 0.19.8

BuildRequires: dbus-devel >= %{dbus_version}
BuildRequires: glib2-devel >= 2.40.0
BuildRequires: gobject-introspection-devel >= 0.10.3
%if %{with ppp}
BuildRequires: ppp-devel >= 2.4.5
%endif
%if %{with crypto_gnutls}
BuildRequires: gnutls-devel >= 2.12
%else
BuildRequires: nss-devel >= 3.11.7
%endif
BuildRequires: readline-devel
BuildRequires: audit-libs-devel
%if %{with regen_docs}
BuildRequires: gtk-doc
%endif
BuildRequires: libudev-devel
BuildRequires: libuuid-devel
BuildRequires: /usr/bin/valac
BuildRequires: libxslt
%if %{with bluetooth}
BuildRequires: bluez-libs-devel
%endif
BuildRequires: systemd >= 200-3 systemd-devel
%if 0%{?fedora}
BuildRequires: libpsl-devel >= 0.1
%endif
BuildRequires: libcurl-devel
BuildRequires: libndp-devel >= 1.0
%if 0%{?with_modem_manager_1}
BuildRequires: ModemManager-glib-devel >= 1.0
%endif
%if %{with wwan}
BuildRequires: mobile-broadband-provider-info-devel
%endif
%if %{with nmtui}
BuildRequires: newt-devel
%endif
BuildRequires: /usr/bin/dbus-launch
BuildRequires: python3
BuildRequires: python3-gobject-base
BuildRequires: python3-dbus
BuildRequires: python3-pexpect
BuildRequires: libselinux-devel
BuildRequires: polkit-devel
BuildRequires: jansson-devel
%if %{with sanitizer}
BuildRequires: libasan
%if 0%{?fedora} || 0%{?rhel} >= 8
BuildRequires: libubsan
%endif
%endif
%if %{with firewalld_zone}
BuildRequires: firewalld-filesystem
%endif
BuildRequires: iproute
%if 0%{?fedora} || 0%{?rhel} >= 8
BuildRequires: iproute-tc
%endif

Provides: %{name}-dispatcher%{?_isa} = %{epoch}:%{version}-%{release}

# NetworkManager uses various parts of systemd-networkd internally, including
# DHCP client, IPv4 Link-Local address negotiation or LLDP support.
# This provide is essentially here so that NetworkManager shows on Security
# Response Team's radar in case a flaw is found. The code is frequently
# synchronized and thus it's not easy to establish a good version number
# here. The version of zero is there just to have something conservative so
# that the scripts that would parse the SPEC file naively would be unlikely
# to fail. Refer to git log for the real date and commit number of last
# synchronization:
# https://gitlab.freedesktop.org/NetworkManager/NetworkManager/commits/main/src/
Provides: bundled(systemd) = 0


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

%description adsl
This package contains NetworkManager support for ADSL devices.
%endif


%if %{with bluetooth}
%package bluetooth
Summary: Bluetooth device plugin for NetworkManager
Group: System Environment/Base
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}
Requires: NetworkManager-wwan = %{epoch}:%{version}-%{release}
%if 0%{?rhel} && 0%{?rhel} <= 7
# No Requires:bluez to prevent it being installed when updating
# to the split NM package
%else
Requires: bluez >= 4.101-5
%endif
Obsoletes: NetworkManager < %{obsoletes_device_plugins}

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
%if 0%{?fedora} || 0%{?rhel} >= 8
# Team was split from main NM binary between 0.9.10 and 1.0
# We need this Obsoletes in addition to the one above
# (git:3aede801521ef7bff039e6e3f1b3c7b566b4338d).
Obsoletes: NetworkManager < 1:1.0.0
%endif

%description team
This package contains NetworkManager support for team devices.
%endif


%if %{with wifi}
%package wifi
Summary: Wifi plugin for NetworkManager
Group: System Environment/Base
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}

%if 0%{?fedora} >= 29 || 0%{?rhel} >= 9
Requires: wireless-regdb
%else
Requires: crda
%endif

%if %{with iwd} && (0%{?fedora} >= 25 || 0%{?rhel} >= 8)
Requires: (wpa_supplicant >= %{wpa_supplicant_version} or iwd)
Suggests: wpa_supplicant
%else
# Just require wpa_supplicant on platforms that don't support boolean
# dependencies even though the plugin supports both supplicant and
# iwd backend.
Requires: wpa_supplicant >= %{wpa_supplicant_version}
%endif

Obsoletes: NetworkManager < %{obsoletes_device_plugins}

%description wifi
This package contains NetworkManager support for Wifi and OLPC devices.
%endif


%if %{with wwan}
%package wwan
Summary: Mobile broadband device plugin for NetworkManager
Group: System Environment/Base
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}
%if 0%{?rhel} && 0%{?rhel} <= 7
# No Requires:ModemManager to prevent it being installed when updating
# to the split NM package
%else
Requires: ModemManager
%endif
Obsoletes: NetworkManager < %{obsoletes_device_plugins}

%description wwan
This package contains NetworkManager support for mobile broadband (WWAN)
devices.
%endif


%if %{with ovs}
%package ovs
Summary: Open vSwitch device plugin for NetworkManager
Group: System Environment/Base
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}
%if 0%{?rhel} == 0
Requires: openvswitch
%endif

%description ovs
This package contains NetworkManager support for Open vSwitch bridges.
%endif


%if %{with ppp}
%package ppp
Summary: PPP plugin for NetworkManager
Group: System Environment/Base
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}
Requires: ppp = %{ppp_version}
Requires: NetworkManager = %{epoch}:%{version}-%{release}
Obsoletes: NetworkManager < %{obsoletes_ppp_plugin}

%description ppp
This package contains NetworkManager support for PPP.
%endif


%package libnm
Summary: Libraries for adding NetworkManager support to applications.
Group: Development/Libraries
Conflicts: NetworkManager-glib < 1:1.31.0
License: LGPL-2.1-or-later

%description libnm
This package contains the libraries that make it easier to use some
NetworkManager functionality from applications.


%package libnm-devel
Summary: Header files for adding NetworkManager support to applications.
Group: Development/Libraries
Requires: %{name}-libnm%{?_isa} = %{epoch}:%{version}-%{release}
Requires: glib2-devel
Requires: pkgconfig
License: LGPL-2.1-or-later

%description libnm-devel
This package contains the header and pkg-config files for development
applications using NetworkManager functionality from applications.


%if %{with connectivity_fedora}
%package config-connectivity-fedora
Summary: NetworkManager config file for connectivity checking via Fedora servers
Group: System Environment/Base
BuildArch: noarch
Provides: NetworkManager-config-connectivity = %{epoch}:%{version}-%{release}

%description config-connectivity-fedora
This adds a NetworkManager configuration file to enable connectivity checking
via Fedora infrastructure.
%endif


%if %{with connectivity_redhat}
%package config-connectivity-redhat
Summary: NetworkManager config file for connectivity checking via Red Hat servers
Group: System Environment/Base
BuildArch: noarch
Provides: NetworkManager-config-connectivity = %{epoch}:%{version}-%{release}

%description config-connectivity-redhat
This adds a NetworkManager configuration file to enable connectivity checking
via Red Hat infrastructure.
%endif


%package config-server
Summary: NetworkManager config file for "server-like" defaults
Group: System Environment/Base
BuildArch: noarch

%description config-server
This adds a NetworkManager configuration file to make it behave more
like the old "network" service. In particular, it stops NetworkManager
from automatically running DHCP on unconfigured ethernet devices, and
allows connections with static IP addresses to be brought up even on
ethernet devices with no carrier.

This package is intended to be installed by default for server
deployments.


%package dispatcher-routing-rules
Summary: NetworkManager dispatcher file for advanced routing rules
Group: System Environment/Base
%if 0%{?split_ifcfg_rh}
Requires: %{name}-initscripts-ifcfg-rh
%endif
BuildArch: noarch
Provides: %{name}-config-routing-rules = %{epoch}:%{version}-%{release}
Obsoletes: %{name}-config-routing-rules < 1:1.31.0

%description dispatcher-routing-rules
This adds a NetworkManager dispatcher file to support networking
configurations using "/etc/sysconfig/network-scripts/rule-NAME" files
(eg, to do policy-based routing).


%if %{with nmtui}
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


%if 0%{?split_ifcfg_rh}
%package initscripts-ifcfg-rh
Summary: NetworkManager plugin for reading and writing connections in ifcfg-rh format
Group: System Environment/Base
Requires: %{name} = %{epoch}:%{version}-%{release}
Obsoletes: NetworkManager < %{obsoletes_ifcfg_rh}

%description initscripts-ifcfg-rh
Installs a plugin for reading and writing connection profiles using
the Red Hat ifcfg format in /etc/sysconfig/network-scripts/.
%endif


%if %{with nm_cloud_setup}
%package cloud-setup
Summary: Automatically configure NetworkManager in cloud
Group: System Environment/Base
Requires: %{name} = %{epoch}:%{version}-%{release}
Requires: %{name}-libnm%{?_isa} = %{epoch}:%{version}-%{release}

%description cloud-setup
Installs a nm-cloud-setup tool that can automatically configure
NetworkManager in cloud environment. Only certain cloud providers
like Aliyun, Azure, EC2, GCP are supported.
%endif


%package initscripts-updown
Summary: Legacy ifup/ifdown scripts for NetworkManager that replace initscripts (network-scripts)
Group: System Environment/Base
BuildArch: noarch
Requires: NetworkManager
Requires: /usr/bin/nmcli
Obsoletes: NetworkManager < %{obsoletes_initscripts_updown}

%description initscripts-updown
Installs alternative ifup/ifdown scripts that talk to NetworkManager.
This is only for backward compatibility with initscripts (network-scripts).
Preferably use nmcli instead.


%prep
%autosetup -p1 -n NetworkManager-%{real_version}


%build
%if %{with meson}
%meson \
	-Db_ndebug=false \
	--warnlevel 2 \
%if %{with test}
	--werror \
%endif
	-Dnft=%{_sbindir}/nft \
	-Diptables=%{_sbindir}/iptables \
	-Ddhclient=%{_sbindir}/dhclient \
	-Ddhcpcanon=no \
	-Ddhcpcd=no \
	-Dconfig_dhcp_default=%{dhcp_default} \
%if %{with crypto_gnutls}
	-Dcrypto=gnutls \
%else
	-Dcrypto=nss \
%endif
%if %{with debug}
	-Dmore_logging=true \
	-Dmore_asserts=10000 \
%else
	-Dmore_logging=false \
	-Dmore_asserts=0 \
%endif
	-Dld_gc=true \
%if %{with lto}
	-D b_lto=true \
%else
	-D b_lto=false \
%endif
	-Dlibaudit=yes-disabled-by-default \
%if 0%{?with_modem_manager_1}
	-Dmodem_manager=true \
%else
	-Dmodem_manager=false \
%endif
%if %{with wifi}
	-Dwifi=true \
%if 0%{?fedora}
	-Dwext=true \
%else
	-Dwext=false \
%endif
%else
	-Dwifi=false \
%endif
%if %{with iwd}
	-Diwd=true \
%else
	-Diwd=false \
%endif
%if %{with bluetooth}
	-Dbluez5_dun=true \
%else
	-Dbluez5_dun=false \
%endif
%if %{with nmtui}
	-Dnmtui=true \
%else
	-Dnmtui=false \
%endif
%if %{with nm_cloud_setup}
	-Dnm_cloud_setup=true \
%else
	-Dnm_cloud_setup=false \
%endif
	-Dvapi=true \
	-Dintrospection=true \
%if %{with regen_docs}
	-Ddocs=true \
%else
	-Ddocs=false \
%endif
	-Dqt=false \
%if %{with team}
	-Dteamdctl=true \
%else
	-Dteamdctl=false \
%endif
%if %{with ovs}
	-Dovs=true \
%else
	-Dovs=false \
%endif
	-Dselinux=true \
	-Dpolkit=true  \
	-Dconfig_auth_polkit_default=true \
	-Dmodify_system=true \
	-Dconcheck=true \
%if 0%{?fedora}
	-Dlibpsl=true \
%else
	-Dlibpsl=false \
%endif
%if %{ebpf_enabled} != "yes"
	-Debpf=false \
%else
	-Debpf=true \
%endif
	-Dsession_tracking=systemd \
	-Dsuspend_resume=systemd \
	-Dsystemdsystemunitdir=%{_unitdir} \
	-Dsystem_ca_path=/etc/pki/tls/cert.pem \
	-Ddbus_conf_dir=%{dbus_sys_dir} \
	-Dtests=yes \
	-Dvalgrind=no \
	-Difcfg_rh=true \
	-Difupdown=false \
%if %{with ppp}
	-Dppp=true \
	-Dpppd="%{_sbindir}/pppd" \
	-Dpppd_plugin_dir="%{_libdir}/pppd/%{ppp_version}" \
%else
	-Dppp=false \
%endif
%if %{with firewalld_zone}
	-Dfirewalld_zone=true \
%else
	-Dfirewalld_zone=false \
%endif
	-Ddist_version=%{version}-%{release} \
%if %{?config_plugins_default_ifcfg_rh}
	-Dconfig_plugins_default=ifcfg-rh \
%endif
%if %{?ifcfg_migrate}
	-Dconfig_migrate_ifcfg_rh_default=true \
%endif
	-Dresolvconf=no \
	-Dnetconfig=no \
	-Dconfig_dns_rc_manager_default=%{dns_rc_manager_default} \
	-Dconfig_logging_backend_default=%{logging_backend_default}

%meson_build

%else
# autotools
%if %{with regen_docs}
gtkdocize
%endif
autoreconf --install --force
%configure \
	--with-runstatedir=%{_rundir} \
	--enable-silent-rules=no \
	--enable-static=no \
	--with-nft=%{_sbindir}/nft \
	--with-iptables=%{_sbindir}/iptables \
	--with-dhclient=%{_sbindir}/dhclient \
	--with-dhcpcd=no \
	--with-dhcpcanon=no \
	--with-config-dhcp-default=%{dhcp_default} \
%if %{with crypto_gnutls}
	--with-crypto=gnutls \
%else
	--with-crypto=nss \
%endif
%if %{with sanitizer}
	--with-address-sanitizer=exec \
%if 0%{?fedora} || 0%{?rhel} >= 8
	--enable-undefined-sanitizer=yes \
%else
	--enable-undefined-sanitizer=no \
%endif
%else
	--with-address-sanitizer=no \
	--enable-undefined-sanitizer=no \
%endif
%if %{with debug}
	--enable-more-logging=yes \
	--with-more-asserts=10000 \
%else
	--enable-more-logging=no \
	--with-more-asserts=0 \
%endif
	--enable-ld-gc=yes \
%if %{with lto}
	--enable-lto=yes \
%else
	--enable-lto=no \
%endif
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
%if %{with iwd}
	--with-iwd=yes \
%else
	--with-iwd=no \
%endif
%if %{with bluetooth}
	--enable-bluez5-dun=yes \
%else
	--enable-bluez5-dun=no \
%endif
%if %{with nmtui}
	--with-nmtui=yes \
%else
	--with-nmtui=no \
%endif
%if %{with nm_cloud_setup}
	--with-nm-cloud-setup=yes \
%else
	--with-nm-cloud-setup=no \
%endif
	--enable-vala=yes \
	--enable-introspection=yes \
%if %{with regen_docs}
	--enable-gtk-doc=yes \
%else
	--enable-gtk-doc=no \
%endif
%if %{with team}
	--enable-teamdctl=yes \
%else
	--enable-teamdctl=no \
%endif
%if %{with ovs}
	--enable-ovs=yes \
%else
	--enable-ovs=no \
%endif
	--with-selinux=yes \
	--enable-polkit=yes \
	--enable-modify-system=yes \
	--enable-concheck=yes \
%if 0%{?fedora}
	--with-libpsl=yes \
%else
	--with-libpsl=no \
%endif
	--with-ebpf=%{ebpf_enabled} \
	--with-session-tracking=systemd \
	--with-suspend-resume=systemd \
	--with-systemdsystemunitdir=%{_unitdir} \
	--with-system-ca-path=/etc/pki/tls/cert.pem \
	--with-dbus-sys-dir=%{dbus_sys_dir} \
	--with-tests=yes \
%if %{with test}
	--enable-more-warnings=error \
%else
	--enable-more-warnings=yes \
%endif
	--with-valgrind=no \
	--enable-ifcfg-rh=yes \
	--enable-ifupdown=no \
%if %{with ppp}
	--enable-ppp=yes \
	--with-pppd="%{_sbindir}/pppd" \
	--with-pppd-plugin-dir="%{_libdir}/pppd/%{ppp_version}" \
%else
	--enable-ppp=no \
%endif
%if %{with firewalld_zone}
	--enable-firewalld-zone=yes \
%else
	--enable-firewalld-zone=no \
%endif
	--with-dist-version=%{version}-%{release} \
%if %{?config_plugins_default_ifcfg_rh}
	--with-config-plugins-default=ifcfg-rh \
%endif
%if %{?ifcfg_migrate}
	--with-config-migrate-ifcfg-rh-default=yes \
%endif
	--with-resolvconf=no \
	--with-netconfig=no \
	--with-config-dns-rc-manager-default=%{dns_rc_manager_default} \
	--with-config-logging-backend-default=%{logging_backend_default}

%make_build

%endif

%install
%if %{with meson}
%meson_install
%else
%make_install
%endif

cp %{SOURCE1} %{buildroot}%{_sysconfdir}/%{name}/

cp %{SOURCE2} %{buildroot}%{nmlibdir}/conf.d/

%if %{with connectivity_fedora}
cp %{SOURCE4} %{buildroot}%{nmlibdir}/conf.d/
%endif

%if %{with connectivity_redhat}
cp %{SOURCE5} %{buildroot}%{nmlibdir}/conf.d/
mkdir -p %{buildroot}%{_sysctldir}
cp %{SOURCE7} %{buildroot}%{_sysctldir}
%endif

%if 0%{?fedora} >= 40
cp %{SOURCE6} %{buildroot}%{nmlibdir}/conf.d/
%endif

%if 0%{?ifcfg_warning}
cp %{SOURCE8} %{buildroot}%{_sysconfdir}/sysconfig/network-scripts
%endif
%if 0%{?ifcfg_migrate}
cp %{SOURCE9} %{buildroot}%{_sysconfdir}/sysconfig/network-scripts/readme-ifcfg-rh.txt
%endif

cp examples/dispatcher/10-ifcfg-rh-routes.sh %{buildroot}%{nmlibdir}/dispatcher.d/
ln -s ../no-wait.d/10-ifcfg-rh-routes.sh %{buildroot}%{nmlibdir}/dispatcher.d/pre-up.d/
ln -s ../10-ifcfg-rh-routes.sh %{buildroot}%{nmlibdir}/dispatcher.d/no-wait.d/

%find_lang %{name}

rm -f %{buildroot}%{_libdir}/*.la
rm -f %{buildroot}%{_libdir}/pppd/%{ppp_version}/*.la
rm -f %{buildroot}%{nmplugindir}/*.la

# Ensure the documentation timestamps are constant to avoid multilib conflicts
find %{buildroot}%{_datadir}/gtk-doc -exec touch --reference configure.ac '{}' \+

%if 0%{?__debug_package} && ! 0%{?flatpak}
mkdir -p %{buildroot}%{_prefix}/src/debug/NetworkManager-%{real_version}
cp valgrind.suppressions %{buildroot}%{_prefix}/src/debug/NetworkManager-%{real_version}
%endif

touch %{buildroot}%{_sbindir}/ifup
touch %{buildroot}%{_sbindir}/ifdown


%check
%if %{with meson}
%if %{with test}
%meson_test
%else
%ninja_test -C %{_vpath_builddir} || :
%endif
%else
# autotools
%if %{with test}
make -k %{?_smp_mflags} check
%else
make -k %{?_smp_mflags} check || :
%endif
%endif


%pre
if [ -f "%{_unitdir}/network-online.target.wants/NetworkManager-wait-online.service" ] ; then
    # older versions used to install this file, effectively always enabling
    # NetworkManager-wait-online.service. We no longer do that and rely on
    # preset.
    # But on package upgrade we must explicitly enable it (rh#1455704).
    systemctl enable NetworkManager-wait-online.service || :
fi


%post
# skip triggering if udevd isn't even accessible, e.g. containers or
# rpm-ostree-based systems
if [ -S /run/udev/control ]; then
    /usr/bin/udevadm control --reload-rules || :
    /usr/bin/udevadm trigger --subsystem-match=net || :
fi
%if %{with firewalld_zone}
%firewalld_reload
%endif

%systemd_post %{systemd_units}


%post initscripts-updown
if [ -f %{_sbindir}/ifup -a ! -L %{_sbindir}/ifup ]; then
    # initscripts package too old, won't let us set an alternative
    /usr/sbin/update-alternatives --remove ifup %{_libexecdir}/nm-ifup >/dev/null 2>&1 || :
else
    /usr/sbin/update-alternatives --install %{_sbindir}/ifup ifup %{_libexecdir}/nm-ifup 50 \
        --slave %{_sbindir}/ifdown ifdown %{_libexecdir}/nm-ifdown
fi


%if %{with nm_cloud_setup}
%post cloud-setup
%systemd_post %{systemd_units_cloud_setup}
%endif


%preun
if [ $1 -eq 0 ]; then
    # Package removal, not upgrade
    /bin/systemctl --no-reload disable NetworkManager.service >/dev/null 2>&1 || :

    # Don't kill networking entirely just on package remove
    #/bin/systemctl stop NetworkManager.service >/dev/null 2>&1 || :
fi
%systemd_preun NetworkManager-wait-online.service NetworkManager-dispatcher.service nm-priv-helper.service


%preun initscripts-updown
if [ $1 -eq 0 ]; then
    /usr/sbin/update-alternatives --remove ifup %{_libexecdir}/nm-ifup >/dev/null 2>&1 || :
fi


%if %{with nm_cloud_setup}
%preun cloud-setup
%systemd_preun %{systemd_units_cloud_setup}
%endif


%postun
/usr/bin/udevadm control --reload-rules || :
/usr/bin/udevadm trigger --subsystem-match=net || :
%if %{with firewalld_zone}
%firewalld_reload
%endif

%systemd_postun %{systemd_units}


%if (0%{?fedora} && 0%{?fedora} < 28) || 0%{?rhel}
%post   libnm -p /sbin/ldconfig
%postun libnm -p /sbin/ldconfig
%endif


%if %{with nm_cloud_setup}
%postun cloud-setup
%systemd_postun %{systemd_units_cloud_setup}
%endif


%files
%{dbus_sys_dir}/org.freedesktop.NetworkManager.conf
%{dbus_sys_dir}/nm-dispatcher.conf
%{dbus_sys_dir}/nm-priv-helper.conf
%if 0%{?split_ifcfg_rh} == 0
%{dbus_sys_dir}/nm-ifcfg-rh.conf
%endif
%{_sbindir}/%{name}
%{_bindir}/nmcli
%{_datadir}/bash-completion/completions/nmcli
%dir %{_sysconfdir}/%{name}
%dir %{_sysconfdir}/%{name}/conf.d
%dir %{_sysconfdir}/%{name}/dispatcher.d
%dir %{_sysconfdir}/%{name}/dispatcher.d/pre-down.d
%dir %{_sysconfdir}/%{name}/dispatcher.d/pre-up.d
%dir %{_sysconfdir}/%{name}/dispatcher.d/no-wait.d
%dir %{_sysconfdir}/%{name}/dnsmasq.d
%dir %{_sysconfdir}/%{name}/dnsmasq-shared.d
%dir %{_sysconfdir}/%{name}/system-connections
%config(noreplace) %{_sysconfdir}/%{name}/NetworkManager.conf
%if 0%{?fedora} >= 40
%{nmlibdir}/conf.d/22-wifi-mac-addr.conf.conf
%endif
%ghost %{_sysconfdir}/%{name}/VPN
%{_bindir}/nm-online
%{_libexecdir}/nm-dhcp-helper
%{_libexecdir}/nm-dispatcher
%{_libexecdir}/nm-initrd-generator
%{_libexecdir}/nm-daemon-helper
%{_libexecdir}/nm-priv-helper
%dir %{_libdir}/%{name}
%dir %{nmplugindir}
%if 0%{?split_ifcfg_rh} == 0
%{nmplugindir}/libnm-settings-plugin-ifcfg-rh.so
%endif
%if %{with nmtui}
%exclude %{_mandir}/man1/nmtui*
%endif
%dir %{nmlibdir}
%dir %{nmlibdir}/conf.d
%dir %{nmlibdir}/dispatcher.d
%dir %{nmlibdir}/dispatcher.d/pre-down.d
%dir %{nmlibdir}/dispatcher.d/pre-up.d
%dir %{nmlibdir}/dispatcher.d/no-wait.d
%dir %{nmlibdir}/VPN
%dir %{nmlibdir}/system-connections
%{_mandir}/man1/*
%{_mandir}/man5/*
%{_mandir}/man7/nmcli-examples.7*
%{_mandir}/man8/nm-initrd-generator.8*
%{_mandir}/man8/NetworkManager.8*
%{_mandir}/man8/NetworkManager-dispatcher.8*
%{_mandir}/man8/NetworkManager-wait-online.service.8*
%dir %{_localstatedir}/lib/NetworkManager
%dir %{_sysconfdir}/sysconfig/network-scripts
%{_datadir}/dbus-1/system-services/org.freedesktop.nm_dispatcher.service
%{_datadir}/dbus-1/system-services/org.freedesktop.nm_priv_helper.service
%{_datadir}/polkit-1/actions/*.policy
%{_prefix}/lib/udev/rules.d/*.rules
%if %{with firewalld_zone}
%{_prefix}/lib/firewalld/zones/nm-shared.xml
%endif
# systemd stuff
%{_unitdir}/NetworkManager.service
%{_unitdir}/NetworkManager-wait-online.service
%{_unitdir}/NetworkManager-dispatcher.service
%{_unitdir}/nm-priv-helper.service
%dir %{_datadir}/doc/NetworkManager/examples
%{_datadir}/doc/NetworkManager/examples/server.conf
%if 0%{?ifcfg_warning} || 0%{?ifcfg_migrate}
%{_sysconfdir}/sysconfig/network-scripts/readme-ifcfg-rh.txt
%endif
%doc NEWS AUTHORS README.md CONTRIBUTING.md
%license COPYING
%license COPYING.LGPL
%license COPYING.GFDL


%if %{with adsl}
%files adsl
%{nmplugindir}/libnm-device-plugin-adsl.so
%else
%exclude %{nmplugindir}/libnm-device-plugin-adsl.so
%endif


%if %{with bluetooth}
%files bluetooth
%{nmplugindir}/libnm-device-plugin-bluetooth.so
%endif


%if %{with team}
%files team
%{nmplugindir}/libnm-device-plugin-team.so
%endif


%if %{with wifi}
%files wifi
%{nmplugindir}/libnm-device-plugin-wifi.so
%endif


%if %{with wwan}
%files wwan
%{nmplugindir}/libnm-device-plugin-wwan.so
%{nmplugindir}/libnm-wwan.so
%endif


%if %{with ovs}
%files ovs
%{nmplugindir}/libnm-device-plugin-ovs.so
%{_unitdir}/NetworkManager.service.d/NetworkManager-ovs.conf
%{_mandir}/man7/nm-openvswitch.7*
%endif


%if %{with ppp}
%files ppp
%{_libdir}/pppd/%{ppp_version}/nm-pppd-plugin.so
%{nmplugindir}/libnm-ppp-plugin.so
%endif


%files libnm -f %{name}.lang
%{_libdir}/libnm.so.*
%{_libdir}/girepository-1.0/NM-1.0.typelib


%files libnm-devel
%dir %{_includedir}/libnm
%{_includedir}/libnm/*.h
%{_libdir}/pkgconfig/libnm.pc
%{_libdir}/libnm.so
%{_datadir}/gir-1.0/NM-1.0.gir
%dir %{_datadir}/gtk-doc/html/libnm
%{_datadir}/gtk-doc/html/libnm/*
%dir %{_datadir}/gtk-doc/html/NetworkManager
%{_datadir}/gtk-doc/html/NetworkManager/*
%{_datadir}/vala/vapi/libnm.deps
%{_datadir}/vala/vapi/libnm.vapi
%{_datadir}/dbus-1/interfaces/*.xml


%if %{with connectivity_fedora}
%files config-connectivity-fedora
%dir %{nmlibdir}
%dir %{nmlibdir}/conf.d
%{nmlibdir}/conf.d/20-connectivity-fedora.conf
%endif


%if %{with connectivity_redhat}
%files config-connectivity-redhat
%dir %{nmlibdir}
%dir %{nmlibdir}/conf.d
%{nmlibdir}/conf.d/20-connectivity-redhat.conf
%{_sysctldir}/70-nm-connectivity.conf
%endif


%files config-server
%dir %{nmlibdir}
%dir %{nmlibdir}/conf.d
%{nmlibdir}/conf.d/00-server.conf


%files dispatcher-routing-rules
%{nmlibdir}/dispatcher.d/10-ifcfg-rh-routes.sh
%{nmlibdir}/dispatcher.d/no-wait.d/10-ifcfg-rh-routes.sh
%{nmlibdir}/dispatcher.d/pre-up.d/10-ifcfg-rh-routes.sh


%if %{with nmtui}
%files tui
%{_bindir}/nmtui
%{_bindir}/nmtui-edit
%{_bindir}/nmtui-connect
%{_bindir}/nmtui-hostname
%{_mandir}/man1/nmtui*
%endif


%if 0%{?split_ifcfg_rh}
%files initscripts-ifcfg-rh
%{nmplugindir}/libnm-settings-plugin-ifcfg-rh.so
%{dbus_sys_dir}/nm-ifcfg-rh.conf
%endif


%if %{with nm_cloud_setup}
%files cloud-setup
%{_libexecdir}/nm-cloud-setup
%{_unitdir}/nm-cloud-setup.service
%{_unitdir}/nm-cloud-setup.timer
%{nmlibdir}/dispatcher.d/90-nm-cloud-setup.sh
%{nmlibdir}/dispatcher.d/no-wait.d/90-nm-cloud-setup.sh
%{nmlibdir}/dispatcher.d/pre-up.d/90-nm-cloud-setup.sh
%{_mandir}/man8/nm-cloud-setup.8*
%endif


%files initscripts-updown
%{_libexecdir}/nm-ifup
%ghost %attr(755, root, root) %{_sbindir}/ifup
%{_libexecdir}/nm-ifdown
%ghost %attr(755, root, root) %{_sbindir}/ifdown


%changelog
__CHANGELOG__
