AC_PREREQ([2.63])

dnl The NM version number
m4_define([nm_major_version], [0])
m4_define([nm_minor_version], [8])
m4_define([nm_micro_version], [999])
m4_define([nm_version],
          [nm_major_version.nm_minor_version.nm_micro_version])

AC_INIT([NetworkManager], [nm_version],
        [http://bugzilla.gnome.org/enter_bug.cgi?product=NetworkManager],
        [NetworkManager])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([1.10 subdir-objects tar-ustar no-dist-gzip dist-bzip2])
AM_MAINTAINER_MODE([enable])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([no])])

dnl Define _SYSTEM_EXTENSIONS for various things like strcasestr()
AC_USE_SYSTEM_EXTENSIONS

dnl
dnl Require programs
dnl
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL

# C++ only required if --enable-qt=yes
AC_PROG_CXX

dnl Initialize libtool
LT_PREREQ([2.2])
LT_INIT([disable-static])

dnl maintainer mode stuff
if test $USE_MAINTAINER_MODE = yes; then
	DISABLE_DEPRECATED="-DG_DISABLE_DEPRECATED"
else
	DISABLE_DEPRECATED=""
fi
AC_SUBST(DISABLE_DEPRECATED)

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
dnl Required headers
dnl
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h paths.h sys/ioctl.h sys/time.h syslog.h unistd.h)

dnl
dnl Checks for typedefs, structures, and compiler characteristics.
dnl
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_HEADER_TIME

dnl
dnl Checks for library functions.
dnl
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_CHECK_FUNCS(select socket uname)

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
dnl Documentation
dnl
AC_ARG_WITH(docs, AS_HELP_STRING([--with-docs], [Build NetworkManager documentation]))
AM_CONDITIONAL(WITH_DOCS, test "x$with_docs" = "xyes")
case $with_docs in
    yes)
        enable_gtk_doc=yes
        ;;
    *)
        with_docs=no
        ;;
esac

dnl
dnl Make sha1.c happy on big endian systems
dnl
AC_C_BIGENDIAN

AC_ARG_WITH(distro, AS_HELP_STRING([--with-distro=DISTRO], [Specify the Linux distribution to target: One of redhat, suse, gentoo, debian, arch, slackware, paldo, mandriva, pardus, linexa or exherbo]))
if test "z$with_distro" = "z"; then
	AC_CHECK_FILE(/etc/redhat-release,with_distro="redhat")
	AC_CHECK_FILE(/etc/SuSE-release,with_distro="suse")
	AC_CHECK_FILE(/etc/fedora-release,with_distro="redhat")
	AC_CHECK_FILE(/etc/gentoo-release,with_distro="gentoo")
	AC_CHECK_FILE(/etc/debian_version,with_distro="debian")
	AC_CHECK_FILE(/etc/arch-release,with_distro="arch")
	AC_CHECK_FILE(/etc/slackware-version,with_distro="slackware")
	AC_CHECK_FILE(/etc/frugalware-release,with_distro="frugalware")
	AC_CHECK_FILE(/etc/mandriva-release,with_distro="mandriva")
	AC_CHECK_FILE(/etc/pardus-release,with_distro="pardus")
	AC_CHECK_FILE(/etc/linexa-release,with_distro="linexa")
	AC_CHECK_FILE(/etc/exherbo-release,with_distro="exherbo")
	if test "z$with_distro" = "z"; then
		with_distro=`lsb_release -is`
	fi
fi
with_distro=`echo ${with_distro} | tr '[[:upper:]]' '[[:lower:]]' `

if test "z$with_distro" = "z"; then
	echo "Linux distribution autodetection failed, you must specify the distribution to target using --with-distro=DISTRO"
	exit 1
else
	case $with_distro in
		redhat|suse|gentoo|debian|slackware|arch|paldo|frugalware|mandriva|pardus|linexa|exherbo) ;;
		*)
			echo "Your distribution (${with_distro}) is not yet supported!  (patches welcome)"
			exit 1
			;;
	esac
fi

AM_CONDITIONAL(TARGET_REDHAT, test x"$with_distro" = xredhat)
if test x"$with_distro" = xredhat; then
  AC_DEFINE(TARGET_REDHAT, 1, [Define if you have Fedora or RHEL])
fi

AM_CONDITIONAL(TARGET_SUSE, test x"$with_distro" = xsuse)
if test x"$with_distro" = xsuse; then
  AC_DEFINE(TARGET_SUSE, 1, [Define if you have OpenSUSE or SLES])
fi

AM_CONDITIONAL(TARGET_GENTOO, test x"$with_distro" = xgentoo)
if test x"$with_distro" = xgentoo; then
  AC_DEFINE(TARGET_GENTOO, 1, [Define if you have Gentoo])
fi

AM_CONDITIONAL(TARGET_DEBIAN, test x"$with_distro" = xdebian)
if test x"$with_distro" = xdebian; then
  AC_DEFINE(TARGET_DEBIAN, 1, [Define if you have Debian])
fi

AM_CONDITIONAL(TARGET_SLACKWARE, test x"$with_distro" = xslackware)
if test x"$with_distro" = xslackware; then
  AC_DEFINE(TARGET_SLACKWARE, 1, [Define if you have Slackware])
fi

AM_CONDITIONAL(TARGET_ARCH, test x"$with_distro" = xarch)
if test x"$with_distro" = xarch; then
  AC_DEFINE(TARGET_ARCH, 1, [Define if you have Arch])
fi

AM_CONDITIONAL(TARGET_PALDO, test x"$with_distro" = xpaldo)
if test x"$with_distro" = xpaldo; then
  AC_DEFINE(TARGET_PALDO, 1, [Define if you have Paldo])
fi

AM_CONDITIONAL(TARGET_FRUGALWARE, test x"$with_distro" = xfrugalware)
if test x"$with_distro" = xfrugalware; then
  AC_DEFINE(TARGET_FRUGALWARE, 1, [Define if you have Frugalware])
fi

AM_CONDITIONAL(TARGET_MANDRIVA, test x"$with_distro" = xmandriva)
if test x"$with_distro" = xmandriva; then
  AC_DEFINE(TARGET_MANDRIVA, 1, [Define if you have Mandriva])
fi

AM_CONDITIONAL(TARGET_PARDUS, test x"$with_distro" = xpardus)
if test x"$with_distro" = xpardus; then
  AC_DEFINE(TARGET_PARDUS, 1, [Define if you have Pardus])
fi

AM_CONDITIONAL(TARGET_LINEXA, test x"$with_distro" = xlinexa)
if test x"$with_distro" = xlinexa; then
  AC_DEFINE(TARGET_LINEXA, 1, [Define if you have linexa])
fi

AM_CONDITIONAL(TARGET_EXHERBO, test x"$with_distro" = xexherbo)
if test x"$with_distro" = xexherbo; then
  AC_DEFINE(TARGET_EXHERBO, 1, [Define if you have Exherbo])
fi

dnl
dnl Distribution version string
dnl
AC_ARG_WITH(dist-version, AS_HELP_STRING([--with-dist-version=<NM-distribution-version>], [Define the NM's distribution version string]), ac_distver=$withval, ac_distver="")
if ! test x"$ac_distver" = x""; then
  AC_DEFINE_UNQUOTED(NM_DIST_VERSION, "$ac_distver", [Define the distribution version string])
fi

AC_MSG_CHECKING([Linux Wireless Extensions >= 18])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
              [[#ifndef __user
                #define __user
                #endif
                #include <sys/types.h>
                #include <linux/types.h>
                #include <sys/socket.h>
                #include <net/if.h>
                #include <wireless.h>]],
              [[#ifndef IWEVGENIE
                #error "not found"
                #endif]])],
        [ac_have_iwevgenie=yes],
        [ac_have_iwevgenie=no])
AC_MSG_RESULT($ac_have_iwevgenie)
if test "$ac_have_iwevgenie" = no; then
	AC_MSG_ERROR(wireless-tools library and development headers >= 28pre9 not installed or not functional)
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
dnl Checks for new dbus-glib property access function
dnl
AC_CHECK_LIB([dbus-glib-1], [dbus_glib_global_set_disable_legacy_property_access], ac_have_dg_prop="1", ac_have_dg_prop="0")
AC_DEFINE_UNQUOTED(HAVE_DBUS_GLIB_DISABLE_LEGACY_PROP_ACCESS, $ac_have_dg_prop, [Define if you have a dbus-glib with dbus_glib_global_set_disable_legacy_property_access()])

PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.1 dbus-glib-1 >= 0.75)
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

PKG_CHECK_MODULES(GLIB, gthread-2.0 glib-2.0 >= 2.22 gobject-2.0)
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES(GMODULE, gmodule-2.0)
AC_SUBST(GMODULE_CFLAGS)
AC_SUBST(GMODULE_LIBS)

PKG_CHECK_MODULES(GUDEV, gudev-1.0 >= 147)
AC_SUBST(GUDEV_CFLAGS)
AC_SUBST(GUDEV_LIBS)

PKG_CHECK_MODULES(GIO, gio-2.0)
AC_SUBST(GIO_CFLAGS)
AC_SUBST(GIO_LIBS)

GOBJECT_INTROSPECTION_CHECK([0.9.6])

# Qt4
PKG_CHECK_MODULES(QT, [Qt >= 4 QtCore QtDBus], [have_qt=yes],[have_qt=no])
AC_ARG_ENABLE(qt, AS_HELP_STRING([--enable-qt], [enable Qt examples]),
                     [enable_qt=${enableval}], [enable_qt=${have_qt}])
if (test "${enable_qt}" = "yes"); then
	if test x"$have_qt" = x"no"; then
		AC_MSG_ERROR(Qt development headers are required)
	fi
	AC_SUBST(QT_CFLAGS)
	AC_SUBST(QT_LIBS)
fi
AM_CONDITIONAL(WITH_QT, test "${enable_qt}" = "yes")


AC_ARG_WITH(udev-dir, AS_HELP_STRING([--with-udev-dir=DIR], [where the udev base directory is]))
if test -n "$with_udev_dir" ; then
	UDEV_BASE_DIR="$with_udev_dir"
else
	UDEV_BASE_DIR="/lib/udev"
fi
AC_SUBST(UDEV_BASE_DIR)

# systemd
AC_ARG_WITH([systemdsystemunitdir],
 AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
 [],
 [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
if test "x$with_systemdsystemunitdir" != xno; then
	AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
fi
AM_CONDITIONAL(HAVE_SYSTEMD, [test -n "$with_systemdsystemunitdir" -a "x$with_systemdsystemunitdir" != xno ])

dnl
dnl Disable ConsoleKit support
dnl
AC_ARG_WITH(ck, AS_HELP_STRING([--without-ck], [Build NetworkManager without ConsoleKit session tracking support]))
AM_CONDITIONAL(WITH_CONSOLEKIT, test x"$with_ck" != xno)
no_ck=0
if test x"$with_ck" = x"no"; then
	no_ck="1"
else
	with_ck="yes"
fi
AC_DEFINE_UNQUOTED(NO_CONSOLEKIT, $no_ck, [Define to disable use of ConsoleKit])

PKG_CHECK_MODULES(LIBNL, libnl-1 >= 1.0-pre8)
AC_SUBST(LIBNL_CFLAGS)
AC_SUBST(LIBNL_LIBS)
NM_LIBNL_CHECK

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

AC_ARG_WITH(crypto, AS_HELP_STRING([--with-crypto=nss | gnutls], [Cryptography library to use for certificate and key operations]),ac_crypto=$withval, ac_crypto=nss)

with_nss=no
with_gnutls=no
if test x"$ac_crypto" = xnss; then
  PKG_CHECK_MODULES(NSS, [nss >= 3.11])

  # Work around a pkg-config bug (fdo #29801) where exists != usable
  AC_PATH_PROG(PKGCONFIG_PATH, pkg-config, no)
  if test x"$PKGCONFIG_PATH" = xno; then
    AC_MSG_ERROR([pkgconfig required but not found])
  else
    FOO=`$PKGCONFIG_PATH --cflags --libs nss`
    if test x"$?" != "x0"; then
      AC_MSG_ERROR([No usable NSS found])
    fi
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

GLIB_GENMARSHAL=`pkg-config --variable=glib_genmarshal glib-2.0`
AC_SUBST(GLIB_GENMARSHAL)

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
		AC_MSG_ERROR(couldn't find pppd.h. pppd development headers are required.))

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


# dhclient support
AC_ARG_WITH([dhclient], AS_HELP_STRING([--with-dhclient=yes|no|path], [Enable dhclient 4.x support]))
# If a full path is given, use that and do not test if it works or not.
case "${with_dhclient}" in
	# NM only works with ISC dhclient - other derivatives don't have
	# the same userland.  dhclient 4.x is required for IPv6 support;
	# with older versions NM won't be able to use DHCPv6.

	/*)
		DHCLIENT_PATH="${with_dhclient}"
		DHCLIENT_VERSION=4
		if test -x "${with_dhclient}"; then
			case `"${with_dhclient}" --version 2>&1` in
				"isc-dhclient-4"*) DHCLIENT_VERSION=4; break;;
				"isc-dhclient-V3"*) DHCLIENT_VERSION=3; break;;
			esac
		fi
		AC_MSG_NOTICE(using dhclient at ${DHCLIENT_PATH})
		;;
	no)	AC_MSG_NOTICE(dhclient support disabled)
		;;
	*)
		AC_MSG_CHECKING(for dhclient)
		for path in /sbin /usr/sbin /usr/pkg/sbin /usr/local/sbin; do
			test -x "${path}/dhclient" || continue
			case `"$path/dhclient" --version 2>&1` in
				"isc-dhclient-4"*) DHCLIENT_PATH="$path/dhclient"; DHCLIENT_VERSION=4; break;;
				"isc-dhclient-V3"*) DHCLIENT_PATH="$path/dhclient"; DHCLIENT_VERSION=3; break;;
			esac
		done
		if test -n "${DHCLIENT_PATH}"; then
			AC_MSG_RESULT($DHCLIENT_PATH)
		else
			AC_MSG_RESULT(no)
		fi
		;;
esac

# dhcpcd support
AC_ARG_WITH([dhcpcd], AS_HELP_STRING([--with-dhcpcd=yes|no|path], [Enable dhcpcd 4.x support]))
# If a full path is given, use that and do not test if it works or not.
case "${with_dhcpcd}" in
	/*)
		DHCPCD_PATH="${with_dhcpcd}"
		AC_MSG_NOTICE(using dhcpcd at ${DHCPCD_PATH})
		;;
	no)	AC_MSG_NOTICE(dhcpcd support disabled)
		;;
	*)
		AC_MSG_CHECKING(for dhcpcd)
		# We fully work with upstream dhcpcd-4
		for path in /sbin /usr/sbin /usr/pkg/sbin /usr/local/sbin; do
			test -x "${path}/dhcpcd" || continue
			case `"$path/dhcpcd" --version 2>/dev/null` in
				"dhcpcd "[123]*);;
				"dhcpcd "*) DHCPCD_PATH="$path/dhcpcd"; break;;
			esac
		done
		if test -n "${DHCPCD_PATH}"; then
			AC_MSG_RESULT($DHCPCD_PATH)
		else
			AC_MSG_RESULT(no)
		fi
		;;
esac

if test -z "$DHCPCD_PATH" -a -z "$DHCLIENT_PATH"; then
	# DHCP clients are not a build time dependency, only runtime.
	# dhclient has been the longtime default for NM and it's in /sbin
	# in most distros, so use it.
	AC_MSG_WARN([Could not find a suitable DHCP client])
	DHCLIENT_PATH=/sbin/dhclient
	AC_MSG_WARN([Falling back to ISC dhclient, ${DHCLIENT_PATH}])
fi
AC_SUBST(DHCLIENT_PATH)
AC_SUBST(DHCLIENT_VERSION)
AC_SUBST(DHCPCD_PATH)

# resolvconf support
AC_ARG_WITH([resolvconf],
	    AS_HELP_STRING([--with-resolvconf=yes|no|path], [Enable resolvconf support]),
	    with_resolvconf="$withval",with_resolvconf=no)
# If a full path is given, use that and do not test if it works or not.
case "${with_resolvconf}" in
	/*)
		RESOLVCONF_PATH="${with_resolvconf}"
		AC_MSG_NOTICE(setting resolvconf path to ${RESOLVCONF_PATH})
		;;
	no)	AC_MSG_NOTICE(resolvconf support disabled)
		;;
	*)
		AC_MSG_CHECKING(for resolvconf)
		for path in /sbin /usr/sbin /usr/pkg/sbin /usr/local/sbin; do
			if test -x "${path}/resolvconf"; then
				RESOLVCONF_PATH="${path}/resolvconf"
				break
			fi
		done
		if test -n "${RESOLVCONF_PATH}"; then
			AC_MSG_RESULT($RESOLVCONF_PATH)
		else
			AC_MSG_RESULT(no)
		fi
		;;
esac
AC_SUBST(RESOLVCONF_PATH)
if test -n "${RESOLVCONF_PATH}"; then
	AC_DEFINE_UNQUOTED(RESOLVCONF_PATH, "$RESOLVCONF_PATH", [Define if you have a resolvconf implementation])
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

NM_COMPILER_WARNINGS

GTK_DOC_CHECK(1.0)

dnl
dnl Tests
dnl
AC_ARG_WITH(tests, AS_HELP_STRING([--with-tests], [Build NetworkManager tests]))
AM_CONDITIONAL(WITH_TESTS, test "x$with_tests" = "xyes")
case $with_tests in
    yes)
        with_tests=yes
        ;;
    *)
        with_tests=no
        ;;
esac


AC_CONFIG_FILES([
Makefile
include/Makefile
include/nm-version.h
src/Makefile
src/tests/Makefile
marshallers/Makefile
src/logging/Makefile
src/dns-manager/Makefile
src/vpn-manager/Makefile
src/dhcp-manager/Makefile
src/dhcp-manager/tests/Makefile
src/ip6-manager/Makefile
src/supplicant-manager/Makefile
src/supplicant-manager/tests/Makefile
src/ppp-manager/Makefile
src/dnsmasq-manager/Makefile
src/modem-manager/Makefile
src/bluez-manager/Makefile
src/settings/Makefile
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
src/settings/tests/Makefile
src/wimax/Makefile
src/backends/Makefile
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
test/Makefile
initscript/Makefile
initscript/RedHat/Makefile
initscript/RedHat/NetworkManager
initscript/Gentoo/Makefile
initscript/Gentoo/NetworkManager
initscript/Debian/Makefile
initscript/Debian/NetworkManager
initscript/Slackware/Makefile
initscript/Slackware/rc.networkmanager
initscript/SUSE/Makefile
initscript/SUSE/networkmanager
initscript/Arch/Makefile
initscript/Arch/networkmanager
initscript/paldo/Makefile
initscript/paldo/NetworkManager
initscript/Mandriva/Makefile
initscript/Mandriva/networkmanager
initscript/linexa/Makefile
initscript/linexa/networkmanager
introspection/Makefile
man/Makefile
man/NetworkManager.8
man/NetworkManager.conf.5
man/nm-system-settings.conf.5
man/nm-tool.1
man/nm-online.1
man/nmcli.1
po/Makefile.in
policy/Makefile
data/Makefile
docs/Makefile
docs/api/Makefile
docs/api/version.xml
docs/libnm-glib/Makefile
docs/libnm-util/Makefile
NetworkManager.pc
examples/Makefile
examples/python/Makefile
examples/C/Makefile
examples/C/glib/Makefile
examples/C/qt/Makefile
])
AC_OUTPUT

echo
echo Distribution target: ${with_distro}
echo 'if this is not correct, please specifiy your distro with --with-distro=DISTRO'

echo 

if test -n "${DHCLIENT_PATH}"; then
	echo ISC dhclient support: ${DHCLIENT_PATH}
	echo ISC dhclient version: ${DHCLIENT_VERSION}
else
	echo ISC dhclient support: no
fi

if test -n "${DHCPCD_PATH}"; then
	echo dhcpcd support: ${DHCPCD_PATH}
else
	echo dhcpcd support: no
fi

if test -n "${with_systemdsystemunitdir}"; then
	echo systemd support: ${with_systemdsystemunitdir}
else
	echo systemd support: no
fi

if test "${enable_polkit}" = "yes"; then
	echo PolicyKit support: yes
else
	echo PolicyKit support: no
fi

if test -n "${with_ck}"; then
	echo ConsoleKit support: ${with_ck}
else
	echo ConsoleKit support: no
fi

if test "${enable_wimax}" = "yes"; then
	echo WiMAX support: yes
else
	echo WiMAX support: no
fi

if test "${enable_ppp}" = "yes"; then
	echo PPP support: yes
else
	echo PPP support: no
fi

echo
echo Building documentation: ${with_docs}
echo Building tests: ${with_tests}
echo

