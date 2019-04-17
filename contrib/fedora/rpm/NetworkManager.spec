# SPEC file to build NetworkManager for testing. It aims for a similar
# configuration as rhel-7.0 and Fedora rawhide
#
# This spec file is not used as is to create official packages for RHEL, Fedora or any
# other distribution.
#
# Note that it contains __PLACEHOLDERS__ that will be replaced by the accompanying 'build.sh' script.


%global dbus_glib_version 0.100

%global wireless_tools_version 1:28-0pre9

%global wpa_supplicant_version 1:1.1

%global ppp_version %(sed -n 's/^#define\\s*VERSION\\s*"\\([^\\s]*\\)"$/\\1/p' %{_includedir}/pppd/patchlevel.h 2>/dev/null | grep . || echo bad)
%global glib2_version %(pkg-config --modversion glib-2.0 2>/dev/null || echo bad)

%global epoch_version 1
%global rpm_version __VERSION__
%global real_version __VERSION__
%global release_version __RELEASE_VERSION__
%global snapshot __SNAPSHOT__
%global git_sha __COMMIT__

%global obsoletes_device_plugins 1:0.9.9.95-1
%global obsoletes_ppp_plugin     1:1.5.3

%global systemd_dir %{_prefix}/lib/systemd/system
%global nmlibdir %{_prefix}/lib/%{name}
%global nmplugindir %{_libdir}/%{name}/%{version}-%{release}

%global _hardened_build 1

%if "x%{?snapshot}" != x
%global snapshot_dot .%{snapshot}
%endif
%if "x%{?git_sha}" != x
%global git_sha_dot .%{git_sha}
%endif

%global snap %{?snapshot_dot}%{?git_sha_dot}

%global real_version_major %(printf '%s' '%{real_version}' | sed -n 's/^\\([1-9][0-9]*\\.[1-9][0-9]*\\)\\.[1-9][0-9]*$/\\1/p')

%global systemd_units NetworkManager.service NetworkManager-wait-online.service NetworkManager-dispatcher.service

###############################################################################

%bcond_with meson
%bcond_without adsl
%bcond_without bluetooth
%bcond_without wwan
%bcond_without team
%bcond_without wifi
%bcond_with iwd
%bcond_without ovs
%bcond_without ppp
%bcond_without nmtui
%bcond_without regen_docs
%bcond_with    debug
%bcond_with    test
%bcond_with    lto
%bcond_with    sanitizer
%if 0%{?fedora} > 28 || 0%{?rhel} > 7
%bcond_with libnm_glib
%else
%bcond_without libnm_glib
%endif
%if 0%{?fedora}
%bcond_without connectivity_fedora
%else
%bcond_with connectivity_fedora
%endif
%if 0%{?rhel} && 0%{?rhel} > 7
%bcond_without connectivity_redhat
%else
%bcond_with connectivity_redhat
%endif
%if 0%{?fedora} > 28 || 0%{?rhel} > 7
%bcond_without crypto_gnutls
%else
%bcond_with crypto_gnutls
%endif

###############################################################################

%if 0%{?fedora}
%global dbus_version 1.9.18
%global dbus_sys_dir %{_datadir}/dbus-1/system.d
%else
%global dbus_version 1.1
%global dbus_sys_dir %{_sysconfdir}/dbus-1/system.d
%endif

%if %{with bluetooth} || %{with wwan}
%global with_modem_manager_1 1
%else
%global with_modem_manager_1 0
%endif

%if 0%{?fedora} >= 31 || 0%{?rhel} > 7
%global dhcp_default internal
%else
%global dhcp_default dhclient
%endif

%if 0%{?fedora} || 0%{?rhel} > 7
%global logging_backend_default journal
%global dns_rc_manager_default symlink
%else
%global logging_backend_default syslog
%global dns_rc_manager_default file
%endif

%if 0%{?rhel}
%global config_plugins_default ifcfg-rh,ibft
%global ibft_enabled yes
%else
%global config_plugins_default ifcfg-rh
%global ibft_enabled no
%endif

%if 0%{?fedora}
# Altough eBPF would be available on Fedora's kernel, it seems
# we often get SELinux denials (rh#1651654). But even aside them,
# bpf(BPF_MAP_CREATE, ...) randomly fails with EPERM. That might
# be related to `ulimit -l`. Anyway, this is not usable at the
# moment.
%global ebpf_enabled no
%else
%global ebpf_enabled no
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

#Source: https://download.gnome.org/sources/NetworkManager/%{real_version_major}/%{name}-%{real_version}.tar.xz
Source: __SOURCE1__
Source1: NetworkManager.conf
Source2: 00-server.conf
Source4: 20-connectivity-fedora.conf
Source5: 20-connectivity-redhat.conf

#Patch1: 0001-some.patch

Requires(post): systemd
Requires(post): /usr/sbin/update-alternatives
Requires(preun): systemd
Requires(preun): /usr/sbin/update-alternatives
Requires(postun): systemd

Requires: dbus >= %{dbus_version}
Requires: glib2 >= %{glib2_version}
Requires: %{name}-libnm%{?_isa} = %{epoch}:%{version}-%{release}
Obsoletes: dhcdbd
Obsoletes: NetworkManager < %{obsoletes_device_plugins}
Obsoletes: NetworkManager < %{obsoletes_ppp_plugin}
Obsoletes: NetworkManager-wimax < 1.2

%if 0%{?rhel} && 0%{?rhel} <= 7
# Kept for RHEL to ensure that wired 802.1x works out of the box
Requires: wpa_supplicant >= 1:1.1
%endif

Conflicts: NetworkManager-vpnc < 1:0.7.0.99-1
Conflicts: NetworkManager-openvpn < 1:0.7.0.99-1
Conflicts: NetworkManager-pptp < 1:0.7.0.99-1
Conflicts: NetworkManager-openconnect < 0:0.7.0.99-1
Conflicts: kde-plasma-networkmanagement < 1:0.9-0.49.20110527git.nm09

BuildRequires: gcc
BuildRequires: libtool
BuildRequires: pkgconfig
%if %{with meson}
BuildRequires: meson
%else
BuildRequires: automake
BuildRequires: autoconf
%endif
BuildRequires: intltool
BuildRequires: gettext-devel

BuildRequires: dbus-devel >= %{dbus_version}
BuildRequires: dbus-glib-devel >= %{dbus_glib_version}
%if 0%{?fedora}
BuildRequires: wireless-tools-devel >= %{wireless_tools_version}
%endif
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
BuildRequires: dhclient
BuildRequires: readline-devel
BuildRequires: audit-libs-devel
%if %{with regen_docs}
BuildRequires: gtk-doc
%endif
BuildRequires: libudev-devel
BuildRequires: libuuid-devel
BuildRequires: /usr/bin/valac
BuildRequires: iptables
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
%if %{with nmtui}
BuildRequires: newt-devel
%endif
BuildRequires: /usr/bin/dbus-launch
%if 0%{?fedora} > 27 || 0%{?rhel} > 7
BuildRequires: python3
BuildRequires: python3-gobject-base
BuildRequires: python3-dbus
%else
BuildRequires: python2
BuildRequires: pygobject3-base
BuildRequires: dbus-python
%endif
BuildRequires: libselinux-devel
BuildRequires: polkit-devel
BuildRequires: jansson-devel
%if %{with sanitizer}
BuildRequires: libasan
%if 0%{?fedora}
BuildRequires: libubsan
%endif
%endif

# NetworkManager uses various parts of systemd-networkd internally, including
# DHCP client, IPv4 Link-Local address negotiation or LLDP support.
# This provide is essentially here so that NetworkManager shows on Security
# Response Team's radar in case a flaw is found. The code is frequently
# synchronized and thus it's not easy to establish a good version number
# here. The version of zero is there just to have something conservative so
# that the scripts that would parse the SPEC file naively would be unlikely
# to fail. Refer to git log for the real date and commit number of last
# synchronization:
# https://gitlab.freedesktop.org/NetworkManager/NetworkManager/commits/master/src/systemd
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
%if 0%{?rhel} && 0%{?rhel} <= 7
# No Requires:bluez to prevent it being installed when updating
# to the split NM package
%else
Requires: bluez >= 4.101-5
%endif
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
%if 0%{?fedora} || 0%{?rhel} >= 8
# Team was split from main NM binary between 0.9.10 and 1.0
# We need this Obsoletes in addition to the one above
# (git:3aede801521ef7bff039e6e3f1b3c7b566b4338d).
Obsoletes: NetworkManager < 1.0.0
%endif

%description team
This package contains NetworkManager support for team devices.
%endif


%if %{with wifi}
%package wifi
Summary: Wifi plugin for NetworkManager
Group: System Environment/Base
Requires: %{name}%{?_isa} = %{epoch}:%{version}-%{release}

%if %{with iwd} && (0%{?fedora} > 24 || 0%{?rhel} > 7)
Requires: (wpa_supplicant >= %{wpa_supplicant_version} or iwd)
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


%package glib
Summary: Libraries for adding NetworkManager support to applications (old API).
Group: Development/Libraries
Requires: dbus >= %{dbus_version}
Requires: dbus-glib >= %{dbus_glib_version}
Conflicts: NetworkManager-libnm < %{epoch}:%{version}-%{release}

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
Conflicts: NetworkManager-glib < %{epoch}:%{version}-%{release}

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
%autosetup -p1 -n NetworkManager-%{real_version}


%build
%if %{with meson}
%meson \
	-Db_ndebug=false \
	--warnlevel 2 \
%if %{with test}
	--werror \
%endif
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
	-Dvapi=true \
	-Dintrospection=true \
%if %{with regen_docs}
	-Ddocs=true \
%else
	-Ddocs=false \
%endif
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
	-Dpolkit_agent=true \
	-Dmodify_system=true \
	-Dconcheck=true \
%if 0%{?fedora}
	-Dlibpsl=true \
%else
	-Dlibpsl=false \
%endif
%if %{ebpf_enabled} != yes
	-Debpf=false \
%else
	-Debpf=true \
%endif
	-Dsession_tracking=systemd \
	-Dsuspend_resume=systemd \
	-Dsystemdsystemunitdir=%{systemd_dir} \
	-Dsystem_ca_path=/etc/pki/tls/cert.pem \
	-Ddbus_conf_dir=%{dbus_sys_dir} \
	-Dtests=yes \
	-Dvalgrind=no \
	-Difcfg_rh=true \
%if %{ibft_enabled} != yes
	-Dibft=false \
%else
	-Dibft=true \
%endif
	-Difupdown=false \
%if %{with ppp}
	-Dpppd_plugin_dir=%{_libdir}/pppd/%{ppp_version} \
	-Dppp=true \
%endif
	-Ddist_version=%{version}-%{release} \
	-Dconfig_plugins_default=%{config_plugins_default} \
	-Dconfig_dns_rc_manager_default=%{dns_rc_manager_default} \
	-Dconfig_logging_backend_default=%{logging_backend_default} \
	-Djson_validation=true \
%if %{with libnm_glib}
	-Dlibnm_glib=true
%else
	-Dlibnm_glib=false
%endif

%meson_build

%else
# autotools
%if %{with regen_docs}
gtkdocize
%endif
autoreconf --install --force
intltoolize --automake --copy --force
%configure \
	--disable-silent-rules \
	--disable-static \
	--with-dhclient=yes \
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
%if 0%{?fedora}
	--enable-undefined-sanitizer \
%endif
%else
	--with-address-sanitizer=no \
	--disable-undefined-sanitizer \
%endif
%if %{with debug}
	--enable-more-logging \
	--with-more-asserts=10000 \
%else
	--disable-more-logging \
	--without-more-asserts \
%endif
	--enable-ld-gc \
%if %{with lto}
	--enable-lto \
%else
	--disable-lto \
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
	--enable-vala=yes \
	--enable-introspection \
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
%if %{with ovs}
	--enable-ovs=yes \
%else
	--enable-ovs=no \
%endif
	--with-selinux=yes \
	--enable-polkit=yes \
	--enable-polkit-agent \
	--enable-modify-system=yes \
	--enable-concheck \
%if 0%{?fedora}
	--with-libpsl \
%else
	--without-libpsl \
%endif
	--with-ebpf=%{ebpf_enabled} \
	--with-session-tracking=systemd \
	--with-suspend-resume=systemd \
	--with-systemdsystemunitdir=%{systemd_dir} \
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
	--enable-config-plugin-ibft=%{ibft_enabled} \
	--enable-ifupdown=no \
%if %{with ppp}
	--with-pppd-plugin-dir=%{_libdir}/pppd/%{ppp_version} \
	--enable-ppp=yes \
%endif
	--with-dist-version=%{version}-%{release} \
	--with-config-plugins-default=%{config_plugins_default} \
	--with-config-dns-rc-manager-default=%{dns_rc_manager_default} \
	--with-config-logging-backend-default=%{logging_backend_default} \
	--enable-json-validation \
%if %{with libnm_glib}
	--with-libnm-glib
%else
	--without-libnm-glib
%endif

make %{?_smp_mflags}

%endif # end autotools

%install
%if %{with meson}
%meson_install
%else
make install DESTDIR=%{buildroot}
%endif

cp %{SOURCE1} %{buildroot}%{_sysconfdir}/%{name}/

cp %{SOURCE2} %{buildroot}%{nmlibdir}/conf.d/

%if %{with connectivity_fedora}
cp %{SOURCE4} %{buildroot}%{nmlibdir}/conf.d/
%endif

%if %{with connectivity_redhat}
cp %{SOURCE5} %{buildroot}%{nmlibdir}/conf.d/
%endif

cp examples/dispatcher/10-ifcfg-rh-routes.sh %{buildroot}%{_sysconfdir}/%{name}/dispatcher.d/
ln -s ../no-wait.d/10-ifcfg-rh-routes.sh %{buildroot}%{_sysconfdir}/%{name}/dispatcher.d/pre-up.d/
ln -s ../10-ifcfg-rh-routes.sh %{buildroot}%{_sysconfdir}/%{name}/dispatcher.d/no-wait.d/

%find_lang %{name}

rm -f %{buildroot}%{_libdir}/*.la
rm -f %{buildroot}%{_libdir}/pppd/%{ppp_version}/*.la
rm -f %{buildroot}%{nmplugindir}/*.la

# Ensure the documentation timestamps are constant to avoid multilib conflicts
find %{buildroot}%{_datadir}/gtk-doc -exec touch --reference configure.ac '{}' \+

%if 0%{?__debug_package}
mkdir -p %{buildroot}%{_prefix}/src/debug/NetworkManager-%{real_version}
cp valgrind.suppressions %{buildroot}%{_prefix}/src/debug/NetworkManager-%{real_version}
%endif

touch %{buildroot}%{_sbindir}/ifup %{buildroot}%{_sbindir}/ifdown


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
%endif # end autotools


%pre
if [ -f "%{systemd_dir}/network-online.target.wants/NetworkManager-wait-online.service" ] ; then
    # older versions used to install this file, effectively always enabling
    # NetworkManager-wait-online.service. We no longer do that and rely on
    # preset.
    # But on package upgrade we must explicitly enable it (rh#1455704).
    systemctl enable NetworkManager-wait-online.service || :
fi


%post
/usr/bin/udevadm control --reload-rules || :
/usr/bin/udevadm trigger --subsystem-match=net || :

%systemd_post %{systemd_units}

%triggerin -- initscripts
if [ -f %{_sbindir}/ifup -a ! -L %{_sbindir}/ifup ]; then
    # initscripts package too old, won't let us set an alternative
    /usr/sbin/update-alternatives --remove ifup %{_libexecdir}/nm-ifup >/dev/null 2>&1 || :
else
    /usr/sbin/update-alternatives --install %{_sbindir}/ifup ifup %{_libexecdir}/nm-ifup 50 \
        --slave %{_sbindir}/ifdown ifdown %{_libexecdir}/nm-ifdown
fi


%preun
if [ $1 -eq 0 ]; then
    # Package removal, not upgrade
    /bin/systemctl --no-reload disable NetworkManager.service >/dev/null 2>&1 || :

    # Don't kill networking entirely just on package remove
    #/bin/systemctl stop NetworkManager.service >/dev/null 2>&1 || :

    /usr/sbin/update-alternatives --remove ifup %{_libexecdir}/nm-ifup >/dev/null 2>&1 || :
fi
%systemd_preun NetworkManager-wait-online.service NetworkManager-dispatcher.service


%postun
/usr/bin/udevadm control --reload-rules || :
/usr/bin/udevadm trigger --subsystem-match=net || :

%systemd_postun %{systemd_units}


%if (0%{?fedora} && 0%{?fedora} < 28) || 0%{?rhel}
%post   glib -p /sbin/ldconfig
%postun glib -p /sbin/ldconfig

%post   libnm -p /sbin/ldconfig
%postun libnm -p /sbin/ldconfig
%endif


%files
%{dbus_sys_dir}/org.freedesktop.NetworkManager.conf
%{dbus_sys_dir}/nm-dispatcher.conf
%{dbus_sys_dir}/nm-ifcfg-rh.conf
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
%config(noreplace) %{_sysconfdir}/%{name}/NetworkManager.conf
%{_bindir}/nm-online
%{_libexecdir}/nm-ifup
%ghost %attr(755, root, root) %{_sbindir}/ifup
%{_libexecdir}/nm-ifdown
%ghost %attr(755, root, root) %{_sbindir}/ifdown
%{_libexecdir}/nm-dhcp-helper
%{_libexecdir}/nm-dispatcher
%{_libexecdir}/nm-iface-helper
%{_libexecdir}/nm-initrd-generator
%dir %{_libdir}/%{name}
%dir %{nmplugindir}
%{nmplugindir}/libnm-settings-plugin*.so
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
%{_mandir}/man7/nmcli-examples.7*
%{_mandir}/man8/*
%dir %{_localstatedir}/lib/NetworkManager
%dir %{_sysconfdir}/NetworkManager/system-connections
%dir %{_sysconfdir}/sysconfig/network-scripts
%{_datadir}/dbus-1/system-services/org.freedesktop.nm_dispatcher.service
%{_datadir}/polkit-1/actions/*.policy
%{_prefix}/lib/udev/rules.d/*.rules
# systemd stuff
%{systemd_dir}/NetworkManager.service
%{systemd_dir}/NetworkManager-wait-online.service
%{systemd_dir}/NetworkManager-dispatcher.service
%dir %{_datadir}/doc/NetworkManager/examples
%{_datadir}/doc/NetworkManager/examples/server.conf
%doc NEWS AUTHORS README CONTRIBUTING TODO
%license COPYING


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
%{systemd_dir}/NetworkManager.service.d/NetworkManager-ovs.conf
%{_mandir}/man7/nm-openvswitch.7*
%endif


%if %{with ppp}
%files ppp
%{_libdir}/pppd/%{ppp_version}/nm-pppd-plugin.so
%{nmplugindir}/libnm-ppp-plugin.so
%endif


%if %{with libnm_glib}
%files glib -f %{name}.lang
%{_libdir}/libnm-glib.so.*
%{_libdir}/libnm-glib-vpn.so.*
%{_libdir}/libnm-util.so.*
%{_libdir}/girepository-1.0/NetworkManager-1.0.typelib
%{_libdir}/girepository-1.0/NMClient-1.0.typelib
%endif


%if %{with libnm_glib}
%files glib-devel
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
%{_datadir}/vala/vapi/libnm-*.deps
%{_datadir}/vala/vapi/libnm-*.vapi
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
%endif


%files config-server
%dir %{nmlibdir}
%dir %{nmlibdir}/conf.d
%{nmlibdir}/conf.d/00-server.conf


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
