AC_PREREQ([2.63])

dnl The NM version number
m4_define([nm_major_version], [0])
m4_define([nm_minor_version], [9])
m4_define([nm_micro_version], [9])
m4_define([nm_nano_version],  [0])
m4_define([nm_version],
          [nm_major_version.nm_minor_version.nm_micro_version.nm_nano_version])

AC_INIT([NetworkManager], [nm_version],
        [http://bugzilla.gnome.org/enter_bug.cgi?product=NetworkManager],
        [NetworkManager])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([1.11 tar-ustar no-dist-gzip dist-bzip2 -Wno-portability])
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

dnl Define _SYSTEM_EXTENSIONS for various things like strcasestr()
AC_USE_SYSTEM_EXTENSIONS

dnl
dnl Require programs
dnl
AC_PROG_CC
AM_PROG_CC_C_O

# C++ only required if --enable-qt=yes
AC_PROG_CXX

dnl Initialize libtool
LT_PREREQ([2.2])
LT_INIT([disable-static])

dnl Version stuff
NM_MAJOR_VERSION=nm_major_version
NM_MINOR_VERSION=nm_minor_version
NM_MICRO_VERSION=nm_micro_version
NM_VERSION=nm_version
AC_SUBST(NM_MAJOR_VERSION)
AC_SUBST(NM_MINOR_VERSION)
AC_SUBST(NM_MICRO_VERSION)
AC_SUBST(NM_VERSION)

dnl
dnl Checks for typedefs, structures, and compiler characteristics.
dnl
AC_TYPE_PID_T

dnl
dnl translation support
dnl
IT_PROG_INTLTOOL([0.40.0])

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.17])

GETTEXT_PACKAGE=NetworkManager
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Gettext package])

dnl
dnl Make sha1.c happy on big endian systems
dnl
AC_C_BIGENDIAN

# NetworkManager paths
AC_SUBST(nmbinary, "$sbindir/$PACKAGE", [NetworkManager binary executable])
AC_SUBST(nmconfdir, "$sysconfdir/$PACKAGE", [NetworkManager configuration directory])
AC_SUBST(nmdatadir, "$datadir/$PACKAGE", [NetworkManager shared data directory])
AC_SUBST(nmstatedir, "$localstatedir/lib/$PACKAGE", [NetworkManager persistent state directory])
AC_SUBST(nmrundir, "$localstatedir/run/$PACKAGE", [NetworkManager runtime state directory])

# Alternative configuration plugins
AC_ARG_ENABLE(ifcfg-rh, AS_HELP_STRING([--enable-ifcfg-rh], [enable ifcfg-rh configuration plugin (Fedora/RHEL)]))
AC_ARG_ENABLE(ifcfg-suse, AS_HELP_STRING([--enable-ifcfg-suse], [enable ifcfg-suse configuration plugin (SUSE)]))
AC_ARG_ENABLE(ifupdown, AS_HELP_STRING([--enable-ifupdown], [enable ifupdown configuration plugin (Debian/Ubuntu)]))
AC_ARG_ENABLE(ifnet, AS_HELP_STRING([--enable-ifnet], [enable ifnet configuration plugin (Gentoo)]))
# Default alternative plugins by distribution
AS_IF([test -z "$enable_ifcfg_rh"], AC_CHECK_FILE(/etc/redhat-release, enable_ifcfg_rh=yes))
AS_IF([test -z "$enable_ifcfg_rh"], AC_CHECK_FILE(/etc/fedora-release, enable_ifcfg_rh=yes))
AS_IF([test -z "$enable_ifcfg_rh"], AC_CHECK_FILE(/etc/mandriva-release, enable_ifcfg_rh=yes))
AS_IF([test -z "$enable_ifcfg_suse"], AC_CHECK_FILE(/etc/SuSE-release, enable_ifcfg_suse=yes))
AS_IF([test -z "$enable_ifupdown"], AC_CHECK_FILE(/etc/debian_version, enable_ifupdown=yes))
AS_IF([test -z "$enable_ifnet"], AC_CHECK_FILE(/etc/gentoo-release, enable_ifnet=yes))
# Otherwise plugins default to "no"
AS_IF([test -z "$enable_ifcfg_rh"], enable_ifcfg_rh=no)
AS_IF([test -z "$enable_ifcfg_suse"], enable_ifcfg_suse=no)
AS_IF([test -z "$enable_ifupdown"], enable_ifupdown=no)
AS_IF([test -z "$enable_ifnet"], enable_ifnet=no)
# Create automake conditionals
AM_CONDITIONAL(CONFIG_PLUGIN_IFCFG_RH, test "$enable_ifcfg_rh" = "yes")
AM_CONDITIONAL(CONFIG_PLUGIN_IFCFG_SUSE, test "$enable_ifcfg_suse" = "yes")
AM_CONDITIONAL(CONFIG_PLUGIN_IFUPDOWN, test "$enable_ifupdown" = "yes")
AM_CONDITIONAL(CONFIG_PLUGIN_IFNET, test "$enable_ifnet" = "yes")
# Code coverage
GNOME_CODE_COVERAGE

dnl
dnl Distribution version string
dnl
AC_ARG_WITH(dist-version, AS_HELP_STRING([--with-dist-version=<NM-distribution-version>], [Define the NM''s distribution version string]), ac_distver=$withval, ac_distver="")
if ! test x"$ac_distver" = x""; then
  AC_DEFINE_UNQUOTED(NM_DIST_VERSION, "$ac_distver", [Define the distribution version string])
fi

dnl
dnl Default to using WEXT but allow it to be disabled
dnl
AC_ARG_WITH(wext, AS_HELP_STRING([--with-wext=yes], [Enable or disable Linux Wireless Extensions]), ac_with_wext=$withval, ac_with_wext="yes")
if test x"$ac_with_wext" = x"yes"; then
	AC_MSG_CHECKING([Linux kernel WEXT headers])
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM(
		      [[#ifndef __user
		        #define __user
		        #endif
		        #include <sys/types.h>
		        #include <linux/types.h>
		        #include <sys/socket.h>
		        #include <linux/wireless.h>]],
		      [[#ifndef IWEVGENIE
		        #error "not found"
		        #endif]])],
		[ac_have_iwevgenie=yes],
		[ac_have_iwevgenie=no])
	AC_MSG_RESULT($ac_have_iwevgenie)
	if test "$ac_have_iwevgenie" = no; then
	       AC_MSG_ERROR(Linux kernel development header linux/wireless.h not installed or not functional)
	fi
	AC_DEFINE(HAVE_WEXT, 1, [Define if you have Linux Wireless Extensions support])
else
	AC_DEFINE(HAVE_WEXT, 0, [Define if you have Linux Wireless Extensions support])
fi
AM_CONDITIONAL(WITH_WEXT, test x"${ac_with_wext}" = x"yes")

AC_MSG_CHECKING([Linux kernel nl80211 headers])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
              [[#ifndef __user
                #define __user
                #endif
                #include <sys/types.h>
                #include <linux/types.h>
                #include <sys/socket.h>
                #include <linux/nl80211.h>]],
              [[int a = NL80211_RATE_INFO_BITRATE; a++;]])],
        [ac_have_nl80211=yes],
        [ac_have_nl80211=no])
AC_MSG_RESULT($ac_have_nl80211)
if test "$ac_have_nl80211" = no; then
	AC_MSG_ERROR(Linux kernel development header linux/nl80211.h not installed or not functional)
fi

dnl
dnl Default to using WEXT but allow it to be disabled
dnl
AC_MSG_CHECKING([Linux kernel VLAN_FLAG_LOOSE_BINDING enum value])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
              [[#ifndef __user
                #define __user
                #endif
                #include <sys/types.h>
                #include <linux/types.h>
                #include <linux/if_vlan.h>]],
              [[unsigned int a = VLAN_FLAG_LOOSE_BINDING;]])],
	[ac_have_vlan_flag_loose_binding=yes],
	[ac_have_vlan_flag_loose_binding=no])
AC_MSG_RESULT($ac_have_vlan_flag_loose_binding)
if test "$ac_have_vlan_flag_loose_binding" = yes; then
	AC_DEFINE(HAVE_VLAN_FLAG_LOOSE_BINDING, 1, [Define if you have VLAN_FLAG_LOOSE_BINDING])
else
	AC_DEFINE(HAVE_VLAN_FLAG_LOOSE_BINDING, 0, [Define if you have VLAN_FLAG_LOOSE_BINDING])
fi

dnl
dnl Checks for libm - needed for pow()
dnl
LT_LIB_M

dnl
dnl Checks for libdl - on certain platforms its part of libc
dnl
AC_CHECK_LIB([dl], [dladdr], LIBDL="-ldl", LIBDL="")
AC_SUBST(LIBDL)

dnl
dnl Checks for dbus-glib
dnl
PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.1 dbus-glib-1 >= 0.94)
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

AC_CHECK_LIB([dbus-glib-1], [dbus_g_method_invocation_get_g_connection], ac_have_gmi_get_con="1", ac_have_gmi_get_con="0")
AC_DEFINE_UNQUOTED(HAVE_DBUS_GLIB_GMI_GET_CONNECTION, $ac_have_gmi_get_con, [Define if you have a dbus-glib with dbus_g_method_invocation_get_g_connection()])

dnl
dnl Only dbus-glib >= 0.100 can use private dbus connections
dnl
PKG_CHECK_MODULES(DBUS_GLIB_100, [dbus-glib-1 >= 0.100], [have_dbus_glib_100=yes],[have_dbus_glib_100=no])
if (test "${have_dbus_glib_100}" = "yes"); then
	AC_DEFINE(HAVE_DBUS_GLIB_100, 1, [Define if you have dbus-glib >= 0.100])
else
	AC_DEFINE(HAVE_DBUS_GLIB_100, 0, [Define if you have dbus-glib >= 0.100])
fi
AM_CONDITIONAL(HAVE_DBUS_GLIB_100, test "${have_dbus_glib_100}" = "yes")

PKG_CHECK_MODULES(GLIB, gio-unix-2.0 >= 2.32 gmodule-2.0)

dnl GLIB_VERSION_MIN_REQUIRED should match the version above.
dnl GLIB_VERSION_MAX_ALLOWED should be the largest version for which there
dnl is a GLIB_CHECK_VERSION check. We currently have to use
dnl G_ENCODE_VERSION(2,34) here rather than GLIB_VERSION_2_34, because
dnl GLib 2.32 did not handle future version defines correctly.

GLIB_CFLAGS="$GLIB_CFLAGS -DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_32 '-DGLIB_VERSION_MAX_ALLOWED=G_ENCODE_VERSION(2,34)'"

AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES(GUDEV, gudev-1.0 >= 165)
AC_SUBST(GUDEV_CFLAGS)
AC_SUBST(GUDEV_LIBS)

GOBJECT_INTROSPECTION_CHECK([0.9.6])

# Qt4
PKG_CHECK_MODULES(QT, [QtCore >= 4 QtDBus QtNetwork], [have_qt=yes],[have_qt=no])
AC_ARG_ENABLE(qt, AS_HELP_STRING([--enable-qt], [enable Qt examples]),
                     [enable_qt=${enableval}], [enable_qt=${have_qt}])
if (test "${enable_qt}" = "yes"); then
	if test x"$have_qt" = x"no"; then
		AC_MSG_ERROR(Qt development headers are required)
	fi
	AC_SUBST(QT_CFLAGS)
	AC_SUBST(QT_LIBS)
	# Check for moc-qt4 and if not found then moc
	QT4_BINDIR=`$PKG_CONFIG QtCore --variable moc_location`
	AC_CHECK_PROGS(MOC, [moc-qt4 moc],, [$QT4_BINDIR:$PATH])
fi
AM_CONDITIONAL(WITH_QT, test "${enable_qt}" = "yes")


AC_ARG_WITH(udev-dir, AS_HELP_STRING([--with-udev-dir=DIR], [where the udev base directory is]))
if test -n "$with_udev_dir" ; then
	UDEV_BASE_DIR="$with_udev_dir"
else
	UDEV_BASE_DIR="/lib/udev"
fi
AC_SUBST(UDEV_BASE_DIR)

# systemd unit support
AC_ARG_WITH([systemdsystemunitdir], AS_HELP_STRING([--with-systemdsystemunitdir=DIR],
	[Directory for systemd service files]))
# default location
AS_IF([test -z "$with_systemdsystemunitdir" && $PKG_CONFIG systemd],
	with_systemdsystemunitdir="\$(prefix)/lib/systemd/system")
AS_IF([test -z "$with_systemdsystemunitdir"], with_systemdsystemunitdir=no)
# add conditional and subst
AM_CONDITIONAL(HAVE_SYSTEMD, [test "$with_systemdsystemunitdir" != no])
if test "$with_systemdsystemunitdir" != no; then
	AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
fi

PKG_CHECK_MODULES(SYSTEMD_200, [systemd >= 200], [have_systemd_200=yes],[have_systemd_200=no])
AM_CONDITIONAL(HAVE_SYSTEMD_200, test "${have_systemd_200}" = "yes")

# session tracking support
AC_MSG_CHECKING([Session tracking support])
AC_ARG_WITH(session-tracking, AS_HELP_STRING([--with-session-tracking=systemd|consolekit|no],
	[Select session tracking support (default: consolekit)]))
# default to consolekit
AS_IF([test -z "$with_session_tracking"], with_session_tracking=consolekit)
AS_IF([test "$with_session_tracking" = "ck"], with_session_tracking=consolekit)
AS_IF([test "$with_session_tracking" = "none"], with_session_tracking=no)
# check value
AS_IF([! (echo "$with_session_tracking" | grep -q -E "^(systemd|consolekit|no)$")],
	AC_MSG_ERROR([--with-session-tracking must be systemd/consolekit/no, not $with_session_tracking]))
# add conditionals and subtitutions
AM_CONDITIONAL(SESSION_TRACKING_CK, test "$with_session_tracking" = "consolekit")
AM_CONDITIONAL(SESSION_TRACKING_SYSTEMD, test "$with_session_tracking" = "systemd")
if test "$with_session_tracking" = "systemd"; then
	PKG_CHECK_MODULES(SYSTEMD_LOGIN, [libsystemd-login])
	AC_SUBST(SYSTEMD_LOGIN_CFLAGS)
	AC_SUBST(SYSTEMD_LOGIN_LIBS)
fi
if test "$with_session_tracking" = "consolekit"; then
	AC_SUBST(CKDB_PATH, /var/run/ConsoleKit/database)
fi
AC_MSG_RESULT($with_session_tracking)

AC_ARG_WITH(suspend-resume, AS_HELP_STRING([--with-suspend-resume=upower|systemd], [Build NetworkManager with specific suspend/resume support]))
if test "z$with_suspend_resume" = "z"; then
    PKG_CHECK_EXISTS([libsystemd-login >= 183], [have_systemd_inhibit=yes], [have_systemd_inhibit=no])
    if test "z${have_systemd_inhibit}" = "zyes"; then
	# Use systemd if it's new enough
	with_suspend_resume="systemd"
    else
	# Fall back to upower
	with_suspend_resume="upower"
    fi
fi

case $with_suspend_resume in
    upower) ;;
    systemd)
	PKG_CHECK_MODULES(SYSTEMD_INHIBIT, [libsystemd-login >= 183])
        ;;
    *)
	AC_MSG_ERROR(--with-suspend-resume must be one of [upower, systemd])
        ;;
esac
AM_CONDITIONAL(SUSPEND_RESUME_UPOWER, test "x$with_suspend_resume" = "xupower")
AM_CONDITIONAL(SUSPEND_RESUME_SYSTEMD, test "x$with_suspend_resume" = "xsystemd")

# libnl support for the linux platform
PKG_CHECK_MODULES(LIBNL, libnl-3.0 >= 3.2.8 libnl-route-3.0 libnl-genl-3.0)
AC_SUBST(LIBNL_CFLAGS)
AC_SUBST(LIBNL_LIBS)

# uuid library
PKG_CHECK_MODULES(UUID, uuid)
AC_SUBST(UUID_CFLAGS)
AC_SUBST(UUID_LIBS)

# Intel WiMAX SDK checks
PKG_CHECK_MODULES(IWMX_SDK, [libiWmxSdk-0 >= 1.5.1], [have_wimax=yes],[have_wimax=no])
AC_ARG_ENABLE(wimax, AS_HELP_STRING([--enable-wimax], [enable WiMAX support]),
                     [enable_wimax=${enableval}], [enable_wimax=${have_wimax}])
if (test "${enable_wimax}" = "yes"); then
	if test x"$have_wimax" = x"no"; then
		AC_MSG_ERROR(Intel WiMAX SDK is required)
	fi

	# Ensure the WiMAX stack is built with libnl3; otherwise crashes happen
	# due to symbol conflicts
	WMX_LIB_PATH=`$PKG_CONFIG --variable=libdir libiWmxSdk-0`
	FOO=`ldd $WMX_LIB_PATH/libiWmxSdk.so.0.0.0 | grep libnl-3 2>&1`
	if test "$?" != "0"; then
		AC_MSG_ERROR([Intel WiMAX stack built with incompatible libnl version!])
	fi

	AC_SUBST(IWMX_SDK_CFLAGS)
	AC_SUBST(IWMX_SDK_LIBS)
	AC_DEFINE(WITH_WIMAX, 1, [Define if you have WiMAX support])
else
	AC_DEFINE(WITH_WIMAX, 0, [Define if you have WiMAX support])
fi
AM_CONDITIONAL(WITH_WIMAX, test "${enable_wimax}" = "yes")

PKG_CHECK_MODULES(POLKIT, [polkit-gobject-1 >= 0.97], [have_polkit=yes],[have_polkit=no])
AC_ARG_ENABLE(polkit, AS_HELP_STRING([--enable-polkit], [enable PolicyKit support]),
                     [enable_polkit=${enableval}], [enable_polkit=${have_polkit}])
if (test "${enable_polkit}" = "yes"); then
	if test x"$have_polkit" = x"no"; then
		AC_MSG_ERROR(PolicyKit development headers are required)
	fi
	AC_SUBST(POLKIT_CFLAGS)
	AC_SUBST(POLKIT_LIBS)
	AC_DEFINE(WITH_POLKIT, 1, [Define if you have PolicyKit support])
else
	AC_DEFINE(WITH_POLKIT, 0, [Define if you have PolicyKit support])
fi
AM_CONDITIONAL(WITH_POLKIT, test "${enable_polkit}" = "yes")

AC_ARG_ENABLE(modify-system,
              AS_HELP_STRING([--enable-modify-system], [Allow users to modify system connections]))
if test "${enable_modify_system}" = "yes"; then
	if ! test "${enable_polkit}" = "yes"; then
		AC_MSG_ERROR([--enable-modify-system requires --enable-polkit])
	fi
	NM_MODIFY_SYSTEM_POLICY="yes"
else
	NM_MODIFY_SYSTEM_POLICY="auth_admin_keep"
fi
AC_SUBST(NM_MODIFY_SYSTEM_POLICY)

AC_ARG_WITH(crypto, AS_HELP_STRING([--with-crypto=nss|gnutls], [Cryptography library to use for certificate and key operations]),ac_crypto=$withval, ac_crypto=nss)

with_nss=no
with_gnutls=no
if test x"$ac_crypto" = xnss; then
  PKG_CHECK_MODULES(NSS, [nss >= 3.11])

  # Work around a pkg-config bug (fdo #29801) where exists != usable
  FOO=`$PKG_CONFIG --cflags --libs nss`
  if test x"$?" != "x0"; then
    AC_MSG_ERROR([No usable NSS found])
  fi

  AC_SUBST(NSS_CFLAGS)
  AC_SUBST(NSS_LIBS)
  AC_DEFINE(HAVE_NSS, 1, [Define if you have NSS])
  with_nss=yes
elif test x"$ac_crypto" = xgnutls; then
  PKG_CHECK_MODULES(GNUTLS, [gnutls >= 1.2])
  AC_PATH_PROG(LIBGCRYPT_CONFIG, libgcrypt-config, no)
  if test x"$LIBGCRYPT_CONFIG" = xno; then
    AC_MSG_ERROR([gnutls explicitly requested but gcrypt not found on system])
  else
    AC_DEFINE(HAVE_GNUTLS, 1, [Define if you have libgnutls])
    LIBGCRYPT_CFLAGS=`$LIBGCRYPT_CONFIG --cflags`
    LIBGCRYPT_LIBS=`$LIBGCRYPT_CONFIG --libs`
    AC_SUBST(LIBGCRYPT_CFLAGS)
    AC_SUBST(LIBGCRYPT_LIBS)
    with_gnutls=yes
  fi
else
  AC_MSG_ERROR([Please choose either 'nss' or 'gnutls' for certificate and crypto operations])
fi
AM_CONDITIONAL(WITH_NSS, test x"$with_nss" != xno)
AM_CONDITIONAL(WITH_GNUTLS, test x"$with_gnutls" != xno)

# Shouldn't ever trigger this, but just in case...
if test x"$ac_nss" = xno -a x"$ac_gnutls" = xno; then
  AC_MSG_ERROR([Could not find required development headers and libraries for '$ac_crypto'])
fi

GLIB_MAKEFILE='$(top_srcdir)/Makefile.glib'
AC_SUBST(GLIB_MAKEFILE)
GLIB_GENMARSHAL=`pkg-config --variable=glib_genmarshal glib-2.0`
AC_SUBST(GLIB_GENMARSHAL)
GLIB_MKENUMS=`pkg-config --variable=glib_mkenums glib-2.0`
AC_SUBST(GLIB_MKENUMS)

AC_ARG_WITH(dbus-sys-dir, AS_HELP_STRING([--with-dbus-sys-dir=DIR], [where D-BUS system.d directory is]))

if test -n "$with_dbus_sys_dir" ; then
    DBUS_SYS_DIR="$with_dbus_sys_dir"
else
    DBUS_SYS_DIR="${sysconfdir}/dbus-1/system.d"
fi
AC_SUBST(DBUS_SYS_DIR)

# pppd
AC_ARG_ENABLE(ppp, AS_HELP_STRING([--enable-ppp], [enable PPP/PPPoE support]),
                     [enable_ppp=${enableval}], [enable_ppp=yes])
if (test "${enable_ppp}" = "yes"); then
	AC_CHECK_HEADERS(pppd/pppd.h,,
		AC_MSG_ERROR("couldn't find pppd.h. pppd development headers are required."))

	AC_DEFINE(WITH_PPP, 1, [Define if you have PPP support])
else
	AC_DEFINE(WITH_PPP, 0, [Define if you have PPP support])
fi
AM_CONDITIONAL(WITH_PPP, test "${enable_ppp}" = "yes")

AC_ARG_WITH([pppd-plugin-dir], AS_HELP_STRING([--with-pppd-plugin-dir=DIR], [path to the pppd plugins directory]))

if test -n "$with_pppd_plugin_dir" ; then
	PPPD_PLUGIN_DIR="$with_pppd_plugin_dir"
else
	PPPD_PLUGIN_DIR="${libdir}/pppd/2.4.5"
fi
AC_SUBST(PPPD_PLUGIN_DIR)

# ModemManager1 with libmm-glib
AC_ARG_WITH(modem-manager-1, AS_HELP_STRING([--with-modem-manager-1], [Enable new ModemManager1 interface support]),,[with_modem_manager_1=auto])
if (test "${with_modem_manager_1}" != "no"); then
    PKG_CHECK_MODULES(MM_GLIB,
                      [mm-glib >= 0.7.991],
                      [have_libmm_glib=yes],
                      [have_libmm_glib=no])
    AC_SUBST(MM_GLIB_CFLAGS)
    AC_SUBST(MM_GLIB_LIBS)

    if (test "${have_libmm_glib}" = "no"); then
        if (test "${with_modem_manager_1}" = "yes"); then
            AC_MSG_ERROR([Couldn't find libmm-glib])
        else
            with_modem_manager_1="no"
        fi
    else
        with_modem_manager_1="yes"
    fi
fi

if (test "${with_modem_manager_1}" = "yes"); then
    AC_DEFINE(WITH_MODEM_MANAGER_1, 1, [Define if you have ModemManager1 support])
else
	AC_DEFINE(WITH_MODEM_MANAGER_1, 0, [Define if you have ModemManager1 support])
fi
AM_CONDITIONAL(WITH_MODEM_MANAGER_1, test "${with_modem_manager_1}" = "yes")

# DHCP client support
AC_ARG_WITH([dhclient], AS_HELP_STRING([--with-dhclient=yes|no|path], [Enable dhclient 4.x support]))
AC_ARG_WITH([dhcpcd], AS_HELP_STRING([--with-dhcpcd=yes|no|path], [Enable dhcpcd 4.x support]))
# Default to "yes"
AS_IF([test -z "$with_dhclient"], with_dhclient=yes)
AS_IF([test -z "$with_dhcpcd"], with_dhcpcd=yes)
# Search and check the executables
if test "$with_dhclient" = "yes"; then
	AC_PATH_PROGS(with_dhclient, dhclient, no, /sbin:/usr/sbin:/usr/local/sbin)
	if test "$with_dhclient" != "no"; then
		if ! $with_dhclient --version 2>&1 | grep -q "^isc-dhclient-4\."; then
			AC_MSG_WARN([Cannot use dhclient, version 4.x is required])
			with_dhclient=no
		fi
	fi
fi
if test "$with_dhcpcd" = "yes"; then
	AC_PATH_PROGS(with_dhcpcd, dhcpcd, no, /sbin:/usr/sbin:/usr/local/sbin)
	if test "$with_dhcpcd" != "no"; then
		if ! $with_dhcpcd --version 2>&1 | grep -q "^dhcpcd [[45]]\."; then
			AC_MSG_WARN([Cannot use dhcpcd, version 4.x or 5.x is required])
			with_dhcpcd=no
		fi
	fi
fi
# Fallback
if test "$with_dhclient" = "no" -a "$with_dhcpcd" = "no"; then
	AC_MSG_WARN([Could not find a suitable DHCP client, falling back to dhclient])
	with_dhclient=/sbin/dhclient
fi
# Add substitutions
if test "$with_dhclient" != "no"; then
	AC_SUBST(DHCLIENT_PATH, $with_dhclient)
fi
if test "$with_dhcpcd" != "no"; then
	AC_SUBST(DHCPCD_PATH, $with_dhcpcd)
fi

# resolvconf and netconfig support
AC_ARG_WITH(resolvconf, AS_HELP_STRING([--with-resolvconf=yes|no|path], [Enable resolvconf support]))
AC_ARG_WITH(netconfig, AS_HELP_STRING([--with-netconfig=yes|no], [Enable SUSE netconfig support]))
# Use netconfig by default on SUSE
AS_IF([test -z "$with_netconfig"], AC_CHECK_FILE(/etc/SuSE-release, with_netconfig=yes))
# Otherwise default to "no"
AS_IF([test -z "$with_resolvconf"], with_resolvconf=no)
AS_IF([test -z "$with_netconfig"], with_netconfig=no)
# Find resolvconf and netconfig
if test "$with_resolvconf" = "yes"; then
	AC_PATH_PROGS(with_resolvconf, resolvconf, no, /sbin:/usr/sbin:/usr/local/sbin)
fi
if test "$with_netconfig" = "yes"; then
	AC_PATH_PROGS(with_netconfig, netconfig, no, /sbin:/usr/sbin:/usr/local/sbin)
fi
# Define resolvconf and netconfig paths
if test "$with_resolvconf" != "no"; then
	AC_DEFINE_UNQUOTED(RESOLVCONF_PATH, "$with_resolvconf", [Path to resolvconf (if enabled)])
fi
if test "$with_netconfig" != "no"; then
	AC_DEFINE_UNQUOTED(NETCONFIG_PATH, "$with_netconfig", [Path to netconfig (if enabled)])
fi

# iptables path
AC_ARG_WITH(iptables, AS_HELP_STRING([--with-iptables=/path/to/iptables], [path to iptables]))
if test "x${with_iptables}" = x; then
  AC_PATH_PROG(IPTABLES_PATH, iptables, [], $PATH:/sbin:/usr/sbin)
  if ! test -x "$IPTABLES_PATH"; then
        AC_MSG_ERROR(iptables was not installed.)
  fi
else
  IPTABLES_PATH="$with_iptables"
fi
AC_DEFINE_UNQUOTED(IPTABLES_PATH, "$IPTABLES_PATH", [Define to path of iptables binary])
AC_SUBST(IPTABLES_PATH)

# system CA certificates path
AC_ARG_WITH(system-ca-path, AS_HELP_STRING([--with-system-ca-path=/path/to/ssl/certs], [path to system CA certificates])) 
if test "x${with_system_ca_path}" = x; then
  SYSTEM_CA_PATH=/etc/ssl/certs
else
  SYSTEM_CA_PATH="$with_system_ca_path"
fi
AC_DEFINE_UNQUOTED(SYSTEM_CA_PATH, "$SYSTEM_CA_PATH", [Define to path to system CA certificates])
AC_SUBST(SYSTEM_CA_PATH)

AC_ARG_WITH(kernel-firmware-dir, AS_HELP_STRING([--with-kernel-firmware-dir=DIR], [where kernel firmware directory is (default is /lib/firmware)]))

if test -n "$with_kernel_firmware_dir" ; then
    KERNEL_FIRMWARE_DIR="$with_kernel_firmware_dir"
else
    KERNEL_FIRMWARE_DIR="/lib/firmware"
fi
AC_DEFINE_UNQUOTED(KERNEL_FIRMWARE_DIR, "$KERNEL_FIRMWARE_DIR", [Define to path of the kernel firmware directory])
AC_SUBST(KERNEL_FIRMWARE_DIR)

PKG_CHECK_MODULES(LIBSOUP, [libsoup-2.4 >= 2.26], [have_libsoup=yes],[have_libsoup=no])
AC_ARG_ENABLE(concheck, AS_HELP_STRING([--enable-concheck], [enable connectivity checking support]),
                     [enable_concheck=${enableval}], [enable_concheck=${have_libsoup}])
if (test "${enable_concheck}" = "yes"); then
	if test x"$have_libsoup" = x"no"; then
		AC_MSG_ERROR(Connectivity checking requires libsoup development headers)
	fi
	AC_SUBST(LIBSOUP_CFLAGS)
	AC_SUBST(LIBSOUP_LIBS)
	AC_DEFINE(WITH_CONCHECK, 1, [Define if you want connectivity checking support])
else
	AC_DEFINE(WITH_CONCHECK, 0, [Define if you want connectivity checking support])
fi
AM_CONDITIONAL(WITH_CONCHECK, test "${enable_concheck}" = "yes")

dnl libndp
AC_ARG_WITH(system-libndp, AS_HELP_STRING([--with-system-libndp=yes|no|auto], [use system libndp rather than bundled one (default: auto)]),
            [with_system_libndp=${withval}], [with_system_libndp=auto])
if test "$with_system_libndp" = yes; then
    PKG_CHECK_MODULES(LIBNDP, [libndp])
elif test "$with_system_libndp" = auto; then
    PKG_CHECK_MODULES(LIBNDP, [libndp], [build_libndp=no],[build_libndp=yes])
else
    build_libndp=yes
fi
AM_CONDITIONAL(BUILD_LIBNDP, test "${build_libndp}" = yes)
if test "$build_libndp" = yes; then
    LIBNDP_CFLAGS='-I$(top_srcdir)/libndp/include'
    LIBNDP_LIBS='$(top_builddir)/libndp/libndp/libndp.la'
    AC_SUBST(LIBNDP_CFLAGS)
    AC_SUBST(LIBNDP_LIBS)
    libndp_location=bundled
else
    # temporary bug workaround
    LIBNDP_CFLAGS=`echo $LIBNDP_CFLAGS | sed -e 's:/ndp.h::'`
    libndp_location=system
fi


NM_COMPILER_WARNINGS

dnl -------------------------
dnl Vala bindings
dnl -------------------------

VAPIGEN_CHECK(0.17.1.24)

# Tests, utilities and documentation
AC_ARG_ENABLE(tests, AS_HELP_STRING([--enable-tests=root|yes|no], [Build NetworkManager tests (default: yes)]))
AC_ARG_WITH(valgrind, AS_HELP_STRING([--with-valgrind=yes|no|path], [Use valgrind to memory-check the tests (default: yes)]))
# Fallback to --with-tests
AC_ARG_WITH(tests, AS_HELP_STRING([--with-tests], [Build NetworkManager tests (deprecated)]))
AS_IF([test -n "$with_tests"], enable_tests="$with_tests")
# Default to --enable-tests --with-valgrind
AS_IF([test -z "$enable_tests"], enable_tests="yes")
AS_IF([test -z "$with_valgrind"], with_valgrind="yes")
# Normalize values
AS_IF([test "$enable_tests" != "yes" -a "$enable_tests" != "root"], enable_tests="no")
# Search for tools
AS_IF([test "$with_valgrind" == "yes"],
	[AC_PATH_PROGS(with_valgrind, valgrind, no)])
# Add conditionals and substitutions
AM_CONDITIONAL(ENABLE_TESTS, test "$enable_tests" != "no")
AM_CONDITIONAL(RUN_ROOT_TESTS, test "$enable_tests" == "root")
AS_IF([test "$with_valgrind" != "no"],
	AC_SUBST(VALGRIND_RULES, "TESTS_ENVIRONMENT = G_SLICE=always-malloc G_DEBUG=gc-friendly \$(LIBTOOL) --mode=execute $with_valgrind --quiet --error-exitcode=1 --leak-check=full --gen-suppressions=all --suppressions=\$(top_srcdir)/valgrind.suppressions"),
	AC_SUBST(VALGRIND_RULES, []))

GTK_DOC_CHECK(1.0)

# check for pregenerated manpages to be installed
install_pregen_manpages=no
if test "$enable_gtk_doc" != "yes" \
	-a -f man/NetworkManager.conf.5 \
	-a -f man/nm-settings.5 \
	-a -f man/NetworkManager.8; then
	install_pregen_manpages=yes
fi
AM_CONDITIONAL(INSTALL_PREGEN_MANPAGES, test "x${install_pregen_manpages}" = "xyes")


AC_CONFIG_FILES([
Makefile
include/Makefile
include/nm-version.h
src/Makefile
src/tests/Makefile
src/config/tests/Makefile
src/dhcp-manager/Makefile
src/dhcp-manager/tests/Makefile
src/supplicant-manager/tests/Makefile
src/ppp-manager/Makefile
src/settings/plugins/Makefile
src/settings/plugins/ifupdown/Makefile
src/settings/plugins/ifupdown/tests/Makefile
src/settings/plugins/ifnet/Makefile
src/settings/plugins/ifnet/tests/Makefile
src/settings/plugins/ifcfg-rh/Makefile
src/settings/plugins/ifcfg-rh/tests/Makefile
src/settings/plugins/ifcfg-rh/tests/network-scripts/Makefile
src/settings/plugins/ifcfg-suse/Makefile
src/settings/plugins/keyfile/Makefile
src/settings/plugins/keyfile/tests/Makefile
src/settings/plugins/keyfile/tests/keyfiles/Makefile
src/settings/plugins/example/Makefile
src/settings/tests/Makefile
src/platform/Makefile
src/platform/tests/Makefile
src/devices/wimax/Makefile
libnm-util/libnm-util.pc
libnm-util/Makefile
libnm-util/tests/Makefile
libnm-util/tests/certs/Makefile
libnm-glib/libnm-glib.pc
libnm-glib/libnm-glib-vpn.pc
libnm-glib/Makefile
libnm-glib/tests/Makefile
callouts/Makefile
callouts/tests/Makefile
tools/Makefile
cli/Makefile
cli/src/Makefile
cli/completion/Makefile
test/Makefile
initscript/RedHat/NetworkManager
initscript/Debian/NetworkManager
initscript/Slackware/rc.networkmanager
initscript/SUSE/networkmanager
initscript/Arch/networkmanager
initscript/Mandriva/networkmanager
initscript/linexa/networkmanager
introspection/Makefile
introspection/all.xml
man/Makefile
man/nm-system-settings.conf.5
man/nm-online.1
man/nmcli.1
po/Makefile.in
policy/Makefile
policy/org.freedesktop.NetworkManager.policy.in
data/Makefile
docs/Makefile
docs/api/Makefile
docs/api/version.xml
docs/libnm-glib/Makefile
docs/libnm-glib/version.xml
docs/libnm-util/Makefile
docs/libnm-util/version.xml
NetworkManager.pc
examples/Makefile
examples/shell/Makefile
examples/python/Makefile
examples/ruby/Makefile
examples/C/Makefile
examples/C/glib/Makefile
examples/C/qt/Makefile
examples/dispatcher/Makefile
vapi/Makefile
])
AC_CONFIG_SUBDIRS([libndp])
AC_OUTPUT

# Print build configuration
echo
echo "System paths:"
echo "  prefix: $prefix"
echo "  exec_prefix: $exec_prefix"
echo "  systemdunitdir: $with_systemdsystemunitdir"
echo "  nmbinary: $nmbinary"
echo "  nmconfdir: $nmconfdir"
echo "  nmdatadir: $nmdatadir"
echo "  nmstatedir: $nmstatedir"
echo "  nmrundir: $nmrundir"
echo

echo "Platform:"
echo "  session tracking: $with_session_tracking"
echo "  suspend/resume: $with_suspend_resume"
if test "${enable_polkit}" = "yes"; then
	if test "${enable_modify_system}" = "yes"; then
		echo "  policykit: yes (permissive modify.system)"
	else
		echo "  policykit: yes (restrictive modify.system)"
	fi
else
	echo  "  policykit: no"
fi
echo

echo "Features:"
echo "  wext: $ac_with_wext"
echo "  wimax: $enable_wimax"
echo "  ppp: $enable_ppp"
echo "  modemmanager-1: $with_modem_manager_1"
echo "  concheck: $enable_concheck"
echo "  libndp: $libndp_location"
echo

echo "Configuration plugins"
echo "  ifcfg-rh: ${enable_ifcfg_rh}"
echo "  ifcfg-suse: ${enable_ifcfg_suse}"
echo "  ifupdown: ${enable_ifupdown}"
echo "  ifnet: ${enable_ifnet}"
echo

echo "Handlers for /etc/resolv.conf:"
echo "  resolvconf: ${with_resolvconf}"
echo "  netconfig: ${with_netconfig}"
echo

echo "DHCP clients:"
echo "  dhclient: $with_dhclient"
echo "  dhcpcd: $with_dhcpcd"
echo

echo "Miscellaneous:"
echo "  documentation: $enable_gtk_doc"
echo "  tests: $enable_tests"
echo "  valgrind: $with_valgrind"
echo "  code coverage: $enable_code_coverage"
echo
