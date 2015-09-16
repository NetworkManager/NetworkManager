AC_PREREQ([2.63])

dnl The NM version number
m4_define([nm_major_version], [1])
m4_define([nm_minor_version], [1])
m4_define([nm_micro_version], [0])
m4_define([nm_version],
          [nm_major_version.nm_minor_version.nm_micro_version])
m4_define([nm_git_sha], [m4_esyscmd([ ( [ -d ./.git/ ] && [ "$(readlink -f ./.git/)" = "$(readlink -f "$(git rev-parse --git-dir 2>/dev/null)" 2>/dev/null)" ] && git rev-parse --verify -q HEAD 2>/dev/null ) || true ])])

AC_INIT([NetworkManager], [nm_version],
        [http://bugzilla.gnome.org/enter_bug.cgi?product=NetworkManager],
        [NetworkManager])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_REQUIRE_AUX_FILE([tap-driver.sh])

AM_INIT_AUTOMAKE(1.12 tar-ustar no-dist-gzip dist-xz -Wno-portability)  dnl NB: Do not [quote] this parameter.
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
NM_GIT_SHA=nm_git_sha
AC_SUBST(NM_MAJOR_VERSION)
AC_SUBST(NM_MINOR_VERSION)
AC_SUBST(NM_MICRO_VERSION)
AC_SUBST(NM_VERSION)
AC_DEFINE_UNQUOTED(NM_GIT_SHA,"$NM_GIT_SHA",[git commit id of the original source code version])

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

# Add runstatedir if not specified manually in autoconf < 2.70
AS_IF([test -z "$runstatedir"], runstatedir="$localstatedir/run")
AC_SUBST(runstatedir)

# NetworkManager paths
AC_SUBST(nmbinary, '${sbindir}'/$PACKAGE, [NetworkManager binary executable])
AC_SUBST(nmconfdir, '${sysconfdir}'/$PACKAGE, [NetworkManager configuration directory])
AC_SUBST(nmlibdir, '${prefix}'/lib/$PACKAGE, [NetworkManager library directory])
AC_SUBST(nmdatadir, '${datadir}'/$PACKAGE, [NetworkManager shared data directory])
AC_SUBST(nmstatedir, '${localstatedir}'/lib/$PACKAGE, [NetworkManager persistent state directory])
AC_SUBST(nmrundir, '${runstatedir}'/$PACKAGE, [NetworkManager runtime state directory])

# Alternative configuration plugins
AC_ARG_ENABLE(config-plugin-ibft, AS_HELP_STRING([--enable-config-plugin-ibft], [enable ibft configuration plugin]))
AC_ARG_ENABLE(ifcfg-rh, AS_HELP_STRING([--enable-ifcfg-rh], [enable ifcfg-rh configuration plugin (Fedora/RHEL)]))
AC_ARG_ENABLE(ifcfg-suse, AS_HELP_STRING([--enable-ifcfg-suse], [enable ifcfg-suse configuration plugin (SUSE) (deprecated)]))
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
# Enable ibft by default
AS_IF([test -z "$enable_config_plugin_ibft"], enable_config_plugin_ibft="yes")
# Create automake conditionals
AM_CONDITIONAL(CONFIG_PLUGIN_IBFT, test "$enable_config_plugin_ibft" = "yes")
AM_CONDITIONAL(CONFIG_PLUGIN_IFCFG_RH, test "$enable_ifcfg_rh" = "yes")
AM_CONDITIONAL(CONFIG_PLUGIN_IFUPDOWN, test "$enable_ifupdown" = "yes")
AM_CONDITIONAL(CONFIG_PLUGIN_IFNET, test "$enable_ifnet" = "yes")

AC_ARG_WITH(config-plugins-default, AS_HELP_STRING([--with-config-plugins-default=PLUGINS], [Default configuration option for main.plugins setting, used as fallback if the configuration option is unset]), [config_plugins_default="$withval"], [config_plugins_default=""])
if test -z "$config_plugins_default" -o "$config_plugins_default" = no; then
    config_plugins_default=''
    test "$enable_ifcfg_rh" = "yes"           && config_plugins_default="$config_plugins_default,ifcfg-rh"
    test "$enable_ifupdown" = "yes"           && config_plugins_default="$config_plugins_default,ifupdown"
    test "$enable_ifnet" = "yes"              && config_plugins_default="$config_plugins_default,ifnet"
    test "$enable_config_plugin_ibft" = "yes" && config_plugins_default="$config_plugins_default,ibft"
    config_plugins_default="${config_plugins_default#,}"
fi

test "$enable_ifcfg_rh" = "yes"           && distro_plugins="$distro_plugins,ifcfg-rh"
test "$enable_ifcfg_suse" = "yes"         && distro_plugins="$distro_plugins,ifcfg-suse"
test "$enable_ifupdown" = "yes"           && distro_plugins="$distro_plugins,ifupdown"
test "$enable_ifnet" = "yes"              && distro_plugins="$distro_plugins,ifnet"
distro_plugins="${distro_plugins#,}"

AC_DEFINE_UNQUOTED(CONFIG_PLUGINS_DEFAULT, "$config_plugins_default", [Default configuration option for main.plugins setting])
if test "${enable_config_plugin_ibft}" = yes; then
	AC_DEFINE(WITH_SETTINGS_PLUGIN_IBFT, 1, [Whether compilation of ibft setting plugin is enabled])
else
	AC_DEFINE(WITH_SETTINGS_PLUGIN_IBFT, 0, [Whether compilation of ibft setting plugin is enabled])
fi

if test "$enable_ifcfg_rh" = "yes"; then
    DISTRO_NETWORK_SERVICE=network.service
fi
AC_SUBST(DISTRO_NETWORK_SERVICE)

# Code coverage
GNOME_CODE_COVERAGE

dnl
dnl Distribution version string
dnl
AC_ARG_WITH(dist-version, AS_HELP_STRING([--with-dist-version=<NM-distribution-version>], [Define the NM''s distribution version string]), ac_distver=$withval, ac_distver="")
if ! test x"$ac_distver" = x""; then
  AC_DEFINE_UNQUOTED(NM_DIST_VERSION, "$ac_distver", [Define the distribution version string])
fi

AC_ARG_ENABLE(wifi, AS_HELP_STRING([--enable-wifi], [enable Wi-Fi support]))
if test "${enable_wifi}" != "no"; then
	enable_wifi='yes'
	AC_DEFINE(WITH_WIFI, 1, [Define if you have Wi-Fi support])
else
	AC_DEFINE(WITH_WIFI, 0, [Define if you have Wi-Fi support])
fi
AM_CONDITIONAL(WITH_WIFI, test "${enable_wifi}" = "yes")

dnl
dnl Default to using WEXT but allow it to be disabled
dnl
AC_ARG_WITH(wext, AS_HELP_STRING([--with-wext=yes], [Enable or disable Linux Wireless Extensions]), ac_with_wext=$withval, ac_with_wext="$enable_wifi")
if test "$ac_with_wext" != 'no'; then
	ac_with_wext='yes'
fi
if test x"$ac_with_wext" = x"yes"; then
	if test "$enable_wifi" != "yes"; then
		AC_MSG_ERROR(Enabling WEXT support and disabling Wi-Fi makes no sense)
	fi
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

if test "$with_wifi" = "yes"; then
	AC_MSG_CHECKING([Linux kernel nl80211 Critical Protocol Start/Stop])
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM(
                  [[#ifndef __user
                    #define __user
                    #endif
                    #include <sys/types.h>
                    #include <linux/types.h>
                    #include <sys/socket.h>
                    #include <linux/nl80211.h>]],
                  [[unsigned int a = NL80211_CMD_CRIT_PROTOCOL_START; a++;]])],
		[ac_have_nl80211_critproto=yes],
		[ac_have_nl80211_critproto=no])
	AC_MSG_RESULT($ac_have_nl80211_critproto)
else
	ac_have_nl80211_critproto='no'
fi
if test "$ac_have_nl80211_critproto" = yes; then
	AC_DEFINE(HAVE_NL80211_CRITICAL_PROTOCOL_CMDS, 1, [Define if nl80211 has critical protocol support])
else
	AC_DEFINE(HAVE_NL80211_CRITICAL_PROTOCOL_CMDS, 0, [Define if nl80211 has critical protocol support])
fi

dnl
dnl Check for newer VLAN flags
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

PKG_CHECK_MODULES(GLIB, [gio-unix-2.0 >= 2.37.6 gmodule-2.0],
	[AC_SUBST(LOG_DRIVER, '$(top_srcdir)/build-aux/tap-driver.sh'),
	 AC_SUBST(AM_TESTS_FD_REDIRECT, '--tap')],
	[PKG_CHECK_MODULES(GLIB, gio-unix-2.0 >= 2.32 gmodule-2.0)
	 AC_SUBST(LOG_DRIVER, '$(top_srcdir)/build-aux/test-driver')])

dnl GLIB_VERSION_MIN_REQUIRED should match the version above.
dnl GLIB_VERSION_MAX_ALLOWED should be set to the same version;
dnl nm-glib.h will cause it to be overridden for the functions
dnl we have compat versions of.
GLIB_CFLAGS="$GLIB_CFLAGS -DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_32 -DGLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_32"

AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

AC_ARG_WITH(libnm-glib, AS_HELP_STRING([--without-libnm-glib], [don't build legacy libraries]))
if test "$with_libnm_glib" != "no"; then
    PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.1 dbus-glib-1 >= 0.94, :,
    			    [AC_MSG_FAILURE([$DBUS_PKG_ERRORS

Configure with --without-libnm-glib if you do not need the legacy libraries])])
    with_libnm_glib=yes
fi
AM_CONDITIONAL(WITH_LEGACY_LIBRARIES, test "$with_libnm_glib" != "no")

PKG_CHECK_MODULES(GUDEV, gudev-1.0 >= 165)

GOBJECT_INTROSPECTION_CHECK([0.9.6])

# Qt4
PKG_CHECK_MODULES(QT, [QtCore >= 4 QtDBus QtNetwork], [have_qt=yes],[have_qt=no])
AC_ARG_ENABLE(qt, AS_HELP_STRING([--enable-qt], [enable Qt examples]),
                     [enable_qt=${enableval}], [enable_qt=${have_qt}])
if (test "${enable_qt}" = "yes"); then
	if test x"$have_qt" = x"no"; then
		AC_MSG_ERROR(Qt development headers are required)
	fi
	# Check for moc-qt4 and if not found then moc
	QT4_BINDIR=`$PKG_CONFIG QtCore --variable moc_location`
	AC_CHECK_PROGS(MOC, [moc-qt4 moc],, [$QT4_BINDIR:$PATH])
fi
AM_CONDITIONAL(WITH_QT, test "${enable_qt}" = "yes")

AC_ARG_WITH(udev-dir, AS_HELP_STRING([--with-udev-dir=DIR], [Absolute path of the udev base directory. Set to 'no' not to install the udev rules]), [], [with_udev_dir="yes"])
if (test "$with_udev_dir" != 'no'); then
	if (test "$with_udev_dir" != 'yes' && printf '%s' "$with_udev_dir" | grep -v -q '^/'); then
		AC_MSG_ERROR([--with-udev-dir must be an absolute path or 'yes' or 'no'. Instead it is '$with_udev_dir'])
	fi
	if (test "$with_udev_dir" = 'yes'); then
		with_udev_dir="/lib/udev"
	fi
	UDEV_DIR="$with_udev_dir"
	AC_SUBST(UDEV_DIR)
fi
AM_CONDITIONAL(WITH_UDEV_DIR, test "$with_udev_dir" != 'no')

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
	AC_DEFINE(HAVE_SYSTEMD, 1, [Define if systemd support is available])
else
	AC_DEFINE(HAVE_SYSTEMD, 0, [Define if systemd support is available])
fi

PKG_CHECK_MODULES(SYSTEMD_200, [systemd >= 200], [have_systemd_200=yes],[have_systemd_200=no])
AM_CONDITIONAL(HAVE_SYSTEMD_200, test "${have_systemd_200}" = "yes")

# Hostname persist mode
AC_ARG_WITH(hostname-persist, AS_HELP_STRING([--with-hostname-persist=default|suse|gentoo],
	[Hostname persist method]))

AS_IF([test "$with_hostname_persist" = "suse"], hostname_persist=suse)
AS_IF([test "$with_hostname_persist" = "gentoo"], hostname_persist=gentoo)
AS_IF([test "$with_hostname_persist" = "default"], hostname_persist=default)
# if the method was not explicitly set, try to guess it from the enabled plugins
AS_IF([test -z "$hostname_persist" -a "$distro_plugins" = "ifcfg-suse"], hostname_persist=suse)
AS_IF([test -z "$hostname_persist" -a "$distro_plugins" = "ifnet"], hostname_persist=gentoo)
AS_IF([test -z "$hostname_persist"], hostname_persist=default)

if test "$hostname_persist" = suse; then
	AC_DEFINE(HOSTNAME_PERSIST_SUSE, 1, [Enable SuSE hostname persist method])
elif test "$hostname_persist" = gentoo; then
	AC_DEFINE(HOSTNAME_PERSIST_GENTOO, 1, [Enable Gentoo hostname persist method])
fi

AC_ARG_WITH(systemd-journal, AS_HELP_STRING([--with-systemd-journal=yes|no], [Use systemd journal for logging]))
have_systemd_journal=no
if test "$with_systemd_journal" != "no"; then
	PKG_CHECK_MODULES(SYSTEMD_JOURNAL,
	                  [libsystemd >= 209],
	                  [have_systemd_journal=yes],
	                  [PKG_CHECK_MODULES(SYSTEMD_JOURNAL,
	                                     [libsystemd-journal],
	                                     [have_systemd_journal=yes],
	                                     [have_systemd_journal=no])])
	if test "$have_systemd_journal" != "yes"; then
		if test "$with_systemd_journal" = "yes"; then
			AC_MSG_ERROR([Missing systemd-journald support])
		fi
	fi
fi
if test "$have_systemd_journal" = "yes"; then
	AC_DEFINE([SYSTEMD_JOURNAL], 1, [Define to 1 if libsystemd-journald is available])
else
	AC_DEFINE([SYSTEMD_JOURNAL], 0, [Define to 1 if libsystemd-journald is available])
fi

AC_ARG_WITH(config-logging-backend-default, AS_HELP_STRING([--with-logging-backend-default=backend], [Default value for logging.backend]), nm_config_logging_backend_default="$withval", nm_config_logging_backend_default="")
if test "$nm_config_logging_backend_default" != 'debug' \
     -a "$nm_config_logging_backend_default" != 'syslog' \
     -a "$nm_config_logging_backend_default" != 'journal' \
     -a "$nm_config_logging_backend_default" != 'journal-syslog-style'; then
	# unknown backend. Reset to default. Silently accept the invalid value to
	# be future proof.
	nm_config_logging_backend_default=''
fi
if test "$nm_config_logging_backend_default" = ""; then
	if test "$have_systemd_journal" = "yes"; then
		nm_config_logging_backend_default='journal-syslog-style'
	else
		nm_config_logging_backend_default='syslog'
	fi
fi
AC_DEFINE_UNQUOTED(NM_CONFIG_LOGGING_BACKEND_DEFAULT, "$nm_config_logging_backend_default", [Default configuration option for logging.backend])
NM_CONFIG_LOGGING_BACKEND_DEFAULT_TEXT="$nm_config_logging_backend_default"
AC_SUBST(NM_CONFIG_LOGGING_BACKEND_DEFAULT_TEXT)

# Session tracking support
AC_ARG_WITH(systemd-logind, AS_HELP_STRING([--with-systemd-logind=yes|no],
	[Support systemd session tracking]))
AC_ARG_WITH(consolekit, AS_HELP_STRING([--with-consolekit=yes|no],
	[Support consolekit session tracking]))
AC_ARG_WITH(session-tracking, AS_HELP_STRING([--with-session-tracking=systemd|consolekit|no],
	[Compatibility option to choose one session tracking module]))
# backwards compatibility
AS_IF([test "$with_session_tracking" = "ck"], [use_consolekit="yes" use_systemd_logind="no"])
AS_IF([test "$with_session_tracking" = "consolekit"], [use_consolekit="yes" use_systemd_logind="no"])
AS_IF([test "$with_session_tracking" = "systemd"], [use_consolekit="no" use_systemd_logind="yes"])
AS_IF([test "$with_session_tracking" = "no"], [use_consolekit="no" use_systemd_logind="no"])
AS_IF([test "$with_session_tracking" = "none"], [use_consolekit="no" use_systemd_logind="no"])
# current options
AS_IF([test -n "$with_systemd_logind" ], [use_systemd_logind="$with_systemd_logind"])
AS_IF([test -n "$with_consolekit" ], [use_consolekit="$with_consolekit"])
# defaults
AS_IF([test -z "$use_systemd_logind"], [use_systemd_logind="auto"])
AS_IF([test -z "$use_consolekit"], [use_consolekit="yes"])
# output
session_tracking=
if test "$use_systemd_logind" = "yes" -o "$use_systemd_logind" = "auto"; then
    PKG_CHECK_MODULES(SYSTEMD_LOGIN, [libsystemd], [have_systemd_logind=yes], [PKG_CHECK_MODULES(SYSTEMD_LOGIN, [libsystemd-login], [have_systemd_logind=yes], [have_systemd_logind=no])])
else
    have_systemd_logind=no
fi
if test "$use_systemd_logind" = "yes" -a "$have_systemd_logind" = "no"; then
    AC_MSG_ERROR([You must have libsystemd installed to build with systemd-logind support.])
fi
if test "$have_systemd_logind" = "yes"; then
	AC_DEFINE([SESSION_TRACKING_SYSTEMD], 1, [Define to 1 if libsystemd-login is available])
	session_tracking="$session_tracking, systemd-logind"
fi
if test "$use_consolekit" = "yes"; then
	AC_DEFINE([SESSION_TRACKING_CONSOLEKIT], 1, [Define to 1 if ConsoleKit is available])
	AC_DEFINE([CKDB_PATH], "/var/run/ConsoleKit/database", [Path to ConsoleKit database])
	session_tracking="$session_tracking, consolekit"
fi
session_tracking="$(printf '%s' "${session_tracking}" | sed 's/^, //')"

AC_ARG_WITH(suspend-resume, AS_HELP_STRING([--with-suspend-resume=upower|systemd|consolekit], [Build NetworkManager with specific suspend/resume support]))
if test "z$with_suspend_resume" = "z"; then
    PKG_CHECK_EXISTS([libsystemd >= 209], [have_systemd_inhibit=yes],
                     [PKG_CHECK_EXISTS([libsystemd-login >= 183], [have_systemd_inhibit=yes], [have_systemd_inhibit=no])])
    if test "z${have_systemd_inhibit}" = "zyes"; then
        # Use systemd if it's new enough
        with_suspend_resume="systemd"
    else
        if test "$use_consolekit" = "yes"; then
                # Use consolekit suspend if session tracking is consolekit
                with_suspend_resume="consolekit"
        else
                # Fall back to upower
                with_suspend_resume="upower"
        fi
    fi
fi

case $with_suspend_resume in
    upower) ;;
    systemd)
        PKG_CHECK_MODULES(SYSTEMD_INHIBIT, [libsystemd >= 209],,
                          [PKG_CHECK_MODULES(SYSTEMD_INHIBIT, [libsystemd-login >= 183])])
        AC_DEFINE([SUSPEND_RESUME_SYSTEMD], 1, [Define to 1 to use systemd suspend api])
        ;;
    consolekit)
        AC_DEFINE([SUSPEND_RESUME_CONSOLEKIT], 1, [Define to 1 to use ConsoleKit2 suspend api])
        ;;
    *)
        AC_MSG_ERROR(--with-suspend-resume must be one of [upower, systemd, consolekit])
        ;;
esac
AM_CONDITIONAL(SUSPEND_RESUME_UPOWER, test "x$with_suspend_resume" = "xupower")
AM_CONDITIONAL(SUSPEND_RESUME_SYSTEMD, test "x$with_suspend_resume" = "xsystemd")
AM_CONDITIONAL(SUSPEND_RESUME_CONSOLEKIT, test "x$with_suspend_resume" = "xconsolekit")

# SELinux support
AC_ARG_WITH(selinux, AS_HELP_STRING([--with-selinux=yes|no|auto], [Build with SELinux (default: auto)]),,[with_selinux=auto])
if test "$with_selinux" = "yes" -o "$with_selinux" = "auto"; then
    PKG_CHECK_MODULES(SELINUX, libselinux, [have_selinux=yes], [have_selinux=no])
else
    have_selinux=no
fi
if test "$with_selinux" = "yes" -a "$have_selinux" = "no"; then
    AC_MSG_ERROR([You must have libselinux installed to build --with-selinux=yes.])
fi
if test "$have_selinux" = "yes"; then
    AC_DEFINE(HAVE_SELINUX, 1, [Define if you have SELinux support])
else
    AC_DEFINE(HAVE_SELINUX, 0, [Define if you have SELinux support])
fi

# libaudit support
AC_ARG_WITH(libaudit, AS_HELP_STRING([--with-libaudit=yes|yes-disabled-by-default|no|auto], [Build with audit daemon support (default: auto). yes-disabled-by-default enables support, but disables it unless explicitly configured via NetworkManager.conf]),,[with_libaudit=auto])
if test "$with_libaudit" = "yes" -o "$with_libaudit" = "yes-disabled-by-default" -o "$with_libaudit" = "auto"; then
    PKG_CHECK_MODULES(LIBAUDIT, audit, [have_libaudit=yes], [have_libaudit=no])
    if test "$with_libaudit" != "auto" -a "$have_libaudit" = "no"; then
        AC_MSG_ERROR([You must have libaudit installed to build --with-libaudit=$with_libaudit.])
    fi
else
    have_libaudit=no
fi
if test "$have_libaudit" = "yes"; then
    AC_DEFINE(HAVE_LIBAUDIT, 1, [Define if you have libaudit support])
	if test "$with_libaudit" = "yes-disabled-by-default"; then
		AC_DEFINE(NM_CONFIG_DEFAULT_LOGGING_AUDIT, FALSE, [The default value of the logging.audit configuration option])
		NM_CONFIG_DEFAULT_LOGGING_AUDIT_TEXT='false'
	else
		AC_DEFINE(NM_CONFIG_DEFAULT_LOGGING_AUDIT, TRUE,  [The default value of the logging.audit configuration option])
		NM_CONFIG_DEFAULT_LOGGING_AUDIT_TEXT='true'
	fi
else
    AC_DEFINE(HAVE_LIBAUDIT, 0, [Define if you have libaudit support])
	AC_DEFINE(NM_CONFIG_DEFAULT_LOGGING_AUDIT, FALSE, [The default value of the logging.audit configuration option])
    NM_CONFIG_DEFAULT_LOGGING_AUDIT_TEXT='false'
fi
AC_SUBST(NM_CONFIG_DEFAULT_LOGGING_AUDIT_TEXT)

# libnl support for the linux platform
PKG_CHECK_MODULES(LIBNL, libnl-3.0 >= 3.2.8 libnl-route-3.0 libnl-genl-3.0)

AC_CHECK_LIB([nl-route-3], [rtnl_link_inet6_get_addr_gen_mode],
	ac_have_addr_gen_mode="1",
	ac_have_addr_gen_mode="0")
AC_DEFINE_UNQUOTED(HAVE_LIBNL_INET6_ADDR_GEN_MODE,
	$ac_have_addr_gen_mode, [Define if libnl has rtnl_link_inet6_get_addr_gen_mode()])

AC_MSG_CHECKING([Linux kernel IN6_ADDR_GEN_MODE enum])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
              [[#ifndef __user
                #define __user
                #endif
                #include <linux/if_link.h>]],
              [[int a = IN6_ADDR_GEN_MODE_EUI64; a++;]])],
        [ac_have_kernel_gen_mode=yes],
        [ac_have_kernel_gen_mode=no])
AC_MSG_RESULT($ac_have_kernel_gen_mode)
if test "$ac_have_kernel_gen_mode" = yes; then
	AC_DEFINE(HAVE_KERNEL_INET6_ADDR_GEN_MODE, 1, [Define if the kernel has IN6_ADDR_GEN_MODE_*])
else
	AC_DEFINE(HAVE_KERNEL_INET6_ADDR_GEN_MODE, 0, [Define if the kernel has IN6_ADDR_GEN_MODE_*])
fi

# IPv6 tokenized identifiers support in libnl
AC_CHECK_LIB([nl-route-3], [rtnl_link_inet6_get_token],
	ac_have_ipv6_token="1",
	ac_have_ipv6_token="0")
AC_DEFINE_UNQUOTED(HAVE_LIBNL_INET6_TOKEN,
	$ac_have_ipv6_token, [Define if libnl has rtnl_link_inet6_get_token()])

# uuid library
PKG_CHECK_MODULES(UUID, uuid)

dnl Checks for readline library - used by nmcli
AX_LIB_READLINE

# Teamd control checks
PKG_CHECK_MODULES(LIBTEAMDCTL, [libteamdctl >= 1.9], [have_teamdctl=yes],[have_teamdctl=no])
AC_ARG_ENABLE(teamdctl, AS_HELP_STRING([--enable-teamdctl], [enable Teamd control support]),
                     [enable_teamdctl=${enableval}], [enable_teamdctl=${have_teamdctl}])
if (test "${enable_teamdctl}" = "yes"); then
	if test x"$have_teamdctl" = x"no"; then
		AC_MSG_ERROR(Teamd control is required)
	fi
	# temporary bug workaround
	LIBTEAMDCTL_CFLAGS=`echo $LIBTEAMDCTL_CFLAGS | sed -e 's:/teamdctl.h::'`
	AC_DEFINE(WITH_TEAMDCTL, 1, [Define if you have Teamd control support])
else
	AC_DEFINE(WITH_TEAMDCTL, 0, [Define if you have Teamd control support])
fi
AM_CONDITIONAL(WITH_TEAMDCTL, test "${enable_teamdctl}" = "yes")

# we usually compile with polkit support. --enable-polkit=yes|no only sets the
# default configuration for main.auth-polkit. User can always enable/disable polkit
# autorization via config. Only when specifying --enable-polkit=disabled, we do
# not compile support. In this case, the user cannot enable polkit authorization via
# configuration.
AC_ARG_ENABLE(polkit, AS_HELP_STRING([--enable-polkit=yes|no|disabled], [set default value for auth-polkit configuration option. This value can be overwritten by NM configuration. 'disabled' compiles NM without any support]),
                     [enable_polkit=${enableval}], [enable_polkit=yes])
if (test "${enable_polkit}" != "no" -a "${enable_polkit}" != "disabled"); then
	enable_polkit=yes
	AC_DEFINE(NM_CONFIG_DEFAULT_AUTH_POLKIT, TRUE, [The default value of the auth-polkit configuration option])
	NM_CONFIG_DEFAULT_AUTH_POLKIT_TEXT='true'
else
	AC_DEFINE(NM_CONFIG_DEFAULT_AUTH_POLKIT, FALSE, [The default value of the auth-polkit configuration option])
	NM_CONFIG_DEFAULT_AUTH_POLKIT_TEXT='false'
fi
if (test "${enable_polkit}" != "disabled"); then
	AC_DEFINE(WITH_POLKIT, 1, [whether to compile polkit support])
else
	AC_DEFINE(WITH_POLKIT, 0, [whether to compile polkit support])
fi
AC_SUBST(NM_CONFIG_DEFAULT_AUTH_POLKIT_TEXT)

PKG_CHECK_MODULES(POLKIT, [polkit-agent-1 >= 0.97], [have_pk_agent=yes],[have_pk_agent=no])
AC_ARG_ENABLE(polkit-agent, AS_HELP_STRING([--enable-polkit-agent], [enable polkit agent for clients]),
                     [enable_polkit_agent=${enableval}], [enable_polkit_agent=${have_pk_agent}])
if (test "${enable_polkit_agent}" = "yes"); then
	if test x"$have_pk_agent" = x"no"; then
		AC_MSG_ERROR(Polkit agent is required)
	fi
	AC_DEFINE(WITH_POLKIT_AGENT, 1, [Define if you have polkit agent])
else
	AC_DEFINE(WITH_POLKIT_AGENT, 0, [Define if you have polkit agent])
fi
AM_CONDITIONAL(WITH_POLKIT_AGENT, test "${enable_polkit_agent}" = "yes")

AC_ARG_ENABLE(modify-system,
              AS_HELP_STRING([--enable-modify-system], [Allow users to modify system connections]))
if test "${enable_modify_system}" = "yes"; then
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

  AC_DEFINE(HAVE_NSS, 1, [Define if you have NSS])
  with_nss=yes
elif test x"$ac_crypto" = xgnutls; then
  PKG_CHECK_MODULES(GNUTLS, [gnutls >= 2.12])
  AC_DEFINE(HAVE_GNUTLS, 1, [Define if you have libgnutls])
  with_gnutls=yes
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
GLIB_GENMARSHAL=`$PKG_CONFIG --variable=glib_genmarshal glib-2.0`
AC_SUBST(GLIB_GENMARSHAL)
GLIB_MKENUMS=`$PKG_CONFIG --variable=glib_mkenums glib-2.0`
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

AC_ARG_WITH(pppd, AS_HELP_STRING([--with-pppd=/path/to/pppd], [path to pppd binary]))
if test "x${with_pppd}" = x; then
  AC_PATH_PROG(PPPD_PATH, pppd, [], $PATH:/sbin:/usr/sbin)
else
  PPPD_PATH="$with_pppd"
fi
AC_DEFINE_UNQUOTED(PPPD_PATH, "$PPPD_PATH", [Define to path of pppd binary])
AC_SUBST(PPPD_PATH)

# ModemManager1 with libmm-glib
AC_ARG_WITH(modem-manager-1, AS_HELP_STRING([--with-modem-manager-1], [Enable new ModemManager1 interface support]),,[with_modem_manager_1=auto])
if (test "${with_modem_manager_1}" != "no"); then
    PKG_CHECK_MODULES(MM_GLIB,
                      [mm-glib >= 0.7.991],
                      [have_libmm_glib=yes],
                      [have_libmm_glib=no])

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

# Bluez5 DUN support
PKG_CHECK_MODULES(BLUEZ5, [bluez >= 5], [have_bluez5=yes],[have_bluez5=no])
AC_ARG_ENABLE(bluez5-dun, AS_HELP_STRING([--enable-bluez5-dun], [enable Bluez5 DUN support]),
		[enable_bluez5_dun=${enableval}], [enable_bluez5_dun=${have_bluez5}])
if (test "${enable_bluez5_dun}" = "yes"); then
	if test x"$have_bluez5" = x"no"; then
		AC_MSG_ERROR(Bluez 5.x development headers are required)
	fi
	AC_DEFINE(WITH_BLUEZ5_DUN, 1, [Define if you have Bluez 5 libraries])
else
	AC_DEFINE(WITH_BLUEZ5_DUN, 0, [Define if you have Bluez 5 libraries])
fi
AM_CONDITIONAL(WITH_BLUEZ5_DUN, test "${enable_bluez5_dun}" = "yes")

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
		if ! $with_dhcpcd --version 2>&1 | grep -q "^dhcpcd [[456789]]\."; then
			AC_MSG_WARN([Cannot use dhcpcd, version 4.x or higher is required])
			with_dhcpcd=no
		elif $with_dhcpcd --version 2>&1 | grep -q "^dhcpcd [[6789]]\."; then
			AC_DEFINE(DHCPCD_SUPPORTS_IPV6, 1, [Define if dhcpcd supports IPv6 (6.x+)])
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
	AC_DEFINE(WITH_DHCLIENT, TRUE, [Define if you have dhclient])
	AC_SUBST(DHCLIENT_PATH, $with_dhclient)
else
	AC_DEFINE(WITH_DHCLIENT, FALSE, [Define if you have dhclient])
fi
if test "$with_dhcpcd" != "no"; then
	AC_DEFINE(WITH_DHCPCD, TRUE, [Define if you have dhcpcd])
	AC_SUBST(DHCPCD_PATH, $with_dhcpcd)
else
	AC_DEFINE(WITH_DHCPCD, FALSE, [Define if you have dhcpcd])
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
	AC_DEFINE_UNQUOTED(RESOLVCONF_PATH, "$with_resolvconf", [Path to resolvconf])
fi
if test "$with_netconfig" != "no"; then
	AC_DEFINE_UNQUOTED(NETCONFIG_PATH, "$with_netconfig", [Path to netconfig])
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

# dnsmasq path
AC_ARG_WITH(dnsmasq, AS_HELP_STRING([--with-dnsmasq=/path/to/dnsmasq], [path to dnsmasq]))
if test "x${with_dnsmasq}" = x; then
  AC_PATH_PROG(DNSMASQ_PATH, dnsmasq, [], $PATH:/sbin:/usr/sbin)
else
  DNSMASQ_PATH="$with_dnsmasq"
fi
AC_DEFINE_UNQUOTED(DNSMASQ_PATH, "$DNSMASQ_PATH", [Define to path of dnsmasq binary])
AC_SUBST(DNSMASQ_PATH)

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
AC_ARG_WITH(libsoup, AS_HELP_STRING([--with-libsoup=yes|no], [Link against libsoup]), [], [with_libsoup=${have_libsoup}])
if test "$with_libsoup" != "no"; then
	if test "$have_libsoup" != "yes"; then
		AC_MSG_ERROR(libsoup library not found)
	fi
	with_libsoup='yes'
	AC_DEFINE(WITH_LIBSOUP, 1, [Define if you have libsoup])
else
	AC_DEFINE(WITH_LIBSOUP, 0, [Define if you have libsoup])
fi
AM_CONDITIONAL(WITH_LIBSOUP, test "$with_libsoup" != "no")

AC_ARG_ENABLE(concheck, AS_HELP_STRING([--enable-concheck], [enable connectivity checking support]),
                     [enable_concheck=${enableval}], [enable_concheck=${with_libsoup}])
if (test "${enable_concheck}" = "yes"); then
	if test x"$with_libsoup" = x"no"; then
		AC_MSG_ERROR(Connectivity checking requires libsoup)
	fi
	AC_DEFINE(WITH_CONCHECK, 1, [Define if you want connectivity checking support])
else
	AC_DEFINE(WITH_CONCHECK, 0, [Define if you want connectivity checking support])
fi
AM_CONDITIONAL(WITH_CONCHECK, test "${enable_concheck}" = "yes")

PKG_CHECK_MODULES(LIBNDP, [libndp])

AC_ARG_WITH(nmtui, AS_HELP_STRING([--with-nmtui=yes|no], [Build nmtui]))
if test "$with_nmtui" != no; then
    PKG_CHECK_MODULES(NEWT, [libnewt >= 0.52.15], [build_nmtui=yes], [build_nmtui=no])
else
    build_nmtui=no
fi
if test "$with_nmtui" = yes -a "$build_nmtui" = no; then
    AC_MSG_ERROR([You must have libnewt installed to build nmtui.])
fi
AM_CONDITIONAL(BUILD_NMTUI, test "$build_nmtui" = yes)


NM_COMPILER_WARNINGS

AC_ARG_ENABLE(more-asserts,
              AS_HELP_STRING([--enable-more-asserts], [Enable more assertions for debugging (default: no)]))
if test "${enable_more_asserts}" = "yes"; then
    AC_DEFINE(NM_MORE_ASSERTS, [1], [Define if more asserts are enabled])
fi

AC_ARG_ENABLE(more-logging,
              AS_HELP_STRING([--enable-more-logging], [Enable more debug logging (default: no)]))
if test "${enable_more_logging}" = "yes"; then
    AC_DEFINE(NM_MORE_LOGGING, [1], [Define if more debug logging is enabled])
fi

AC_ARG_ENABLE(lto, AS_HELP_STRING([--enable-lto], [Enable Link Time Optimization for smaller size (default: no)]))
if (test "${enable_lto}" = "yes"); then
    CFLAGS="-flto $CFLAGS"
else
    enable_lto='no'
fi


dnl -------------------------
dnl Vala bindings
dnl -------------------------

VAPIGEN_CHECK(0.17.1.24)

# Tests, utilities and documentation
AC_ARG_ENABLE(tests, AS_HELP_STRING([--enable-tests=root|yes|no], [Build NetworkManager tests (default: yes)]))
AC_ARG_WITH(valgrind, AS_HELP_STRING([--with-valgrind=yes|no|path], [Use valgrind to memory-check the tests (default: no)]))
# Fallback to --with-tests
AC_ARG_WITH(tests, AS_HELP_STRING([--with-tests], [Build NetworkManager tests (deprecated)]))
AS_IF([test -n "$with_tests"], enable_tests="$with_tests")
# Default to --enable-tests --with-valgrind=no
AS_IF([test -z "$enable_tests"], enable_tests="yes")
AS_IF([test -z "$with_valgrind"], with_valgrind="no")
# Normalize values
AS_IF([test "$enable_tests" != "yes" -a "$enable_tests" != "root"], enable_tests="no")
# Search for tools
AS_IF([test "$with_valgrind" == "yes"],
	[AC_PATH_PROGS(with_valgrind, valgrind, no)])
# Add conditionals and substitutions
AM_CONDITIONAL(ENABLE_TESTS, test "$enable_tests" != "no")
AM_CONDITIONAL(REQUIRE_ROOT_TESTS, test "$enable_tests" == "root")
AC_ARG_WITH(valgrind-suppressions, AS_HELP_STRING([--with-valgrind-suppressions=path], [Use specific valgrind suppression file]))
if test "$with_valgrind" == no; then
	with_valgrind_suppressions=
else
	if test  "$with_valgrind_suppressions" == ""; then
		with_valgrind_suppressions='$(top_srcdir)/valgrind.suppressions'
	fi
fi
AS_IF([test "$with_valgrind" != "no"],
	AC_SUBST(VALGRIND_RULES, 'LOG_COMPILER = "$(top_srcdir)/tools/run-test-valgrind.sh" "$(LIBTOOL)" "$(with_valgrind)" '"$with_valgrind_suppressions"),
	AC_SUBST(VALGRIND_RULES, []))
AM_CONDITIONAL(WITH_VALGRIND, test "${with_valgrind}" != "no")

GTK_DOC_CHECK(1.0)

# check for pregenerated manpages to be installed
install_pregen_manpages=no
if test "$enable_gtk_doc" != "yes" \
	-a -f man/NetworkManager.conf.5 \
	-a -f man/nm-settings.5 \
	-a -f man/nm-settings-keyfile.5 \
	-a -f man/nm-settings-ifcfg-rh.5 \
	-a -f man/nmcli-examples.5 \
	-a -f man/NetworkManager.8; then
	install_pregen_manpages=yes
fi
AM_CONDITIONAL(INSTALL_PREGEN_MANPAGES, test "x${install_pregen_manpages}" = "xyes")

# check if we can build setting property documentation
if test -n "$INTROSPECTION_MAKEFILE" -a "$enable_gtk_doc" = "yes"; then
    # If g-i is installed we know we have python, but we might not have pygobject
    if python -c 'from gi.repository import GObject' >& /dev/null; then
        have_pyobject=yes
    fi

    # gtk-doc depends on perl, but we can check for it anyway
    AC_PATH_PROG(PERL, perl, no)
    # check for needed perl modules (use YAML; YAML::XS is better, but may not be so widespread)
    required_perl_modules="YAML"
    for module in $required_perl_modules; do
      AC_MSG_CHECKING([checking for perl module '$module'])
      if ${PERL} -e 'use '$module 2>/dev/null ; then
          AC_MSG_RESULT([Ok])
          have_perl_modules=yes
      else
          AC_MSG_RESULT([Failed])
          AC_MSG_ERROR([You must have Perl modules to build settings plugin docs: $required_perl_modules.])
      fi
    done

    if test "$have_pyobject" = "yes" -a "$have_perl_modules" = "yes"; then
        AC_DEFINE(BUILD_SETTING_DOCS, [1], [Define if you we can build nm-setting-docs.xml, nm-keyfile-docs.xml and nm-ifcfg-rh-docs.xml])
        build_setting_docs=yes
    fi
fi

# check for pre-built setting docs
if test "$build_setting_docs" != "yes" \
	-a -f man/nm-settings.xml \
	-a -f man/nm-settings-keyfile.xml \
	-a -f man/nm-settings-ifcfg-rh.xml \
	-a -f docs/api/settings-spec.xml \
	-a -f clients/cli/settings-docs.c; then
    AC_DEFINE(HAVE_SETTING_DOCS, [1], [Define if you have pre-built settings docs])
    have_setting_docs=yes
fi

AM_CONDITIONAL(BUILD_SETTING_DOCS, test "$build_setting_docs" = "yes")
AM_CONDITIONAL(SETTING_DOCS_AVAILABLE, test "$build_setting_docs" = "yes" -o "$have_setting_docs" = "yes")


AC_CONFIG_FILES([
Makefile
include/Makefile
src/Makefile
src/tests/Makefile
src/tests/config/Makefile
src/dhcp-manager/Makefile
src/dhcp-manager/tests/Makefile
src/dnsmasq-manager/tests/Makefile
src/supplicant-manager/tests/Makefile
src/supplicant-manager/tests/certs/Makefile
src/ppp-manager/Makefile
src/settings/plugins/Makefile
src/settings/plugins/ifupdown/Makefile
src/settings/plugins/ifupdown/tests/Makefile
src/settings/plugins/ifnet/Makefile
src/settings/plugins/ifnet/tests/Makefile
src/settings/plugins/ifcfg-rh/Makefile
src/settings/plugins/ifcfg-rh/tests/Makefile
src/settings/plugins/ifcfg-rh/tests/network-scripts/Makefile
src/settings/plugins/ibft/Makefile
src/settings/plugins/ibft/tests/Makefile
src/settings/plugins/keyfile/Makefile
src/settings/plugins/keyfile/tests/Makefile
src/settings/plugins/keyfile/tests/keyfiles/Makefile
src/platform/Makefile
src/platform/tests/Makefile
src/rdisc/Makefile
src/rdisc/tests/Makefile
src/devices/adsl/Makefile
src/devices/bluetooth/Makefile
src/devices/team/Makefile
src/devices/wifi/Makefile
src/devices/wifi/tests/Makefile
src/devices/wwan/Makefile
libnm-core/nm-version.h
libnm-core/Makefile
libnm-core/tests/Makefile
libnm/libnm.pc
libnm/Makefile
libnm/tests/Makefile
libnm-util/libnm-util.pc
libnm-util/nm-version.h
libnm-util/Makefile
libnm-util/tests/Makefile
libnm-glib/libnm-glib.pc
libnm-glib/libnm-glib-vpn.pc
libnm-glib/Makefile
libnm-glib/tests/Makefile
callouts/Makefile
callouts/tests/Makefile
tools/Makefile
clients/Makefile
clients/cli/Makefile
clients/tui/Makefile
clients/tui/newt/Makefile
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
man/NetworkManager.conf.xml
man/nm-system-settings.conf.5
man/nm-online.1
man/nmcli.1
man/nmtui.1
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
docs/libnm/Makefile
docs/libnm/version.xml
NetworkManager.pc
examples/Makefile
examples/shell/Makefile
examples/python/Makefile
examples/python/dbus/Makefile
examples/python/gi/Makefile
examples/ruby/Makefile
examples/lua/Makefile
examples/lua/lgi/Makefile
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
echo "  nmlibdir: $nmlibdir"
echo "  nmdatadir: $nmdatadir"
echo "  nmstatedir: $nmstatedir"
echo "  nmrundir: $nmrundir"
echo

echo "Platform:"
echo "  session tracking: $session_tracking"
echo "  suspend/resume: $with_suspend_resume"
if test "${enable_polkit}" = "yes"; then
	if test "${enable_modify_system}" = "yes"; then
		echo "  policykit: yes (permissive modify.system) (default: main.auth-polkit=${enable_polkit})"
	else
		echo "  policykit: yes (restrictive modify.system) (default: main.auth-polkit=${enable_polkit})"
	fi
else
	echo  "  policykit: no"
fi
echo "  polkit agent: ${enable_polkit_agent}"
echo "  selinux: $have_selinux"
echo "  systemd-journald: $have_systemd_journal (default: logging.backend=${nm_config_logging_backend_default})"
echo "  hostname persist: ${hostname_persist}"
echo "  libaudit: $have_libaudit (default: logging.audit=${NM_CONFIG_DEFAULT_LOGGING_AUDIT_TEXT})"
echo

echo "Features:"
echo "  wext: $ac_with_wext"
echo "  wifi: $enable_wifi"
echo "  ppp: $enable_ppp"
echo "  modemmanager-1: $with_modem_manager_1"
echo "  concheck: $enable_concheck"
echo "  libteamdctl: $enable_teamdctl"
echo "  libnm-glib: $with_libnm_glib"
echo "  nmtui: $build_nmtui"
echo

echo "Configuration plugins (main.plugins=${config_plugins_default})"
echo "  ibft: ${enable_config_plugin_ibft}"
echo "  ifcfg-rh: ${enable_ifcfg_rh}"
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
echo "  valgrind: $with_valgrind   $with_valgrind_suppressions"
echo "  code coverage: $enable_code_coverage"
echo "  LTO: $enable_lto"
echo
