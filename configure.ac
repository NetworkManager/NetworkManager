AC_PREREQ([2.63])

dnl The NM version number
dnl
dnl NOTE: When incrementing version also:
dnl  - add corresponding NM_VERSION_x_y_z macros in
dnl    "shared/nm-version-macros.h.in"
dnl  - update number in meson.build
m4_define([nm_major_version], [1])
m4_define([nm_minor_version], [19])
m4_define([nm_micro_version], [4])
m4_define([nm_version],
          [nm_major_version.nm_minor_version.nm_micro_version])

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

AC_PROG_LN_S
AC_PROG_MKDIR_P

# Prefer gcc-* variants; the ones libtool would choose don't work with LTO
AC_CHECK_TOOLS(AR, [gcc-ar ar], false)
AC_CHECK_TOOLS(RANLIB, [gcc-ranlib ranlib], :)
AC_CHECK_TOOLS(NM, [$BINUTILS_NM gcc-nm nm])

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

GIT_SHA_RECORD(NM_GIT_SHA)

dnl
dnl Checks for typedefs, structures, and compiler characteristics.
dnl
AC_TYPE_PID_T
AC_CHECK_SIZEOF(dev_t)
AC_CHECK_SIZEOF(time_t)
AC_CHECK_SIZEOF(pid_t)

AC_CHECK_DECLS([
	explicit_bzero],
	[], [], [[
#include <string.h>
]])

AC_CHECK_DECLS([
	reallocarray],
	[], [], [[
#include <malloc.h>
]])

AC_CHECK_DECLS([
	memfd_create],
	[], [], [[
#include <sys/mman.h>
]])

AC_CHECK_HEADERS(sys/auxv.h)

AC_CHECK_DECLS([getrandom],
               [AC_DEFINE([USE_SYS_RANDOM_H], [1], [sys/random.h is usable])
                AC_DEFINE([HAVE_GETRANDOM], [1], [has getrandom])
               ],
               [AC_CHECK_DECLS([getrandom],
                               [AC_DEFINE([USE_SYS_RANDOM_H], [0], [sys/random.h is usable])
                                AC_DEFINE([HAVE_GETRANDOM], [1], [has getrandom])],
                               [AC_DEFINE([USE_SYS_RANDOM_H], [0], [sys/random.h is usable])
                                AC_DEFINE([HAVE_GETRANDOM], [0], [has getrandom])],
                               [[#include <linux/random.h>
                                 ]])],
               [[#include <sys/random.h>
                 ]])

dnl
dnl translation support
dnl
IT_PROG_INTLTOOL([0.40.0])

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.17])

GETTEXT_PACKAGE=NetworkManager
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Gettext package])

# autoconf 2.70 adds option --runstatedir. To make the directory also configurable
# on older versions, add --with-runstatedir option. Note that this option overwrites
# --runstatedir (should it be set). If you know to use autoconf >= 2.70, you should
# instead use --runstatedir.
AC_ARG_WITH([runstatedir],
            AS_HELP_STRING([--with-runstatedir=DIR],
                           [Directory for /var/run. Defaults to $localstatedir/run. In autoconf >= 2.70, you should instead use --runstatedir option. This option takes precedence over --runstatedir.]),
            [runstatedir="$withval"])
AS_IF([test -z "$runstatedir"], runstatedir="$localstatedir/run")
AC_SUBST(runstatedir)

# NetworkManager paths
AC_SUBST(nmbinary, '${sbindir}'/$PACKAGE, [NetworkManager binary executable])
AC_SUBST(nmconfdir, '${sysconfdir}'/$PACKAGE, [NetworkManager configuration directory])
AC_SUBST(nmlibdir, '${prefix}'/lib/$PACKAGE, [NetworkManager library directory])
AC_SUBST(nmdatadir, '${datadir}'/$PACKAGE, [NetworkManager shared data directory])
AC_SUBST(nmstatedir, '${localstatedir}'/lib/$PACKAGE, [NetworkManager persistent state directory])
AC_SUBST(nmrundir, '${runstatedir}'/$PACKAGE, [NetworkManager runtime state directory])

AC_GNU_SOURCE
AC_CHECK_FUNCS([__secure_getenv secure_getenv])

# Alternative configuration plugins
AC_ARG_ENABLE(ifcfg-rh, AS_HELP_STRING([--enable-ifcfg-rh], [enable ifcfg-rh configuration plugin (Fedora/RHEL)]))
AC_ARG_ENABLE(ifupdown, AS_HELP_STRING([--enable-ifupdown], [enable ifupdown configuration plugin (Debian/Ubuntu)]))
# Default alternative plugins by distribution
AS_IF([test -z "$enable_ifcfg_rh" -a -d /etc/sysconfig/network-scripts], enable_ifcfg_rh=yes)
AS_IF([test -z "$enable_ifupdown" -a -f /etc/debian_version],            enable_ifupdown=yes)
# Otherwise plugins default to "no"
AS_IF([test -z "$enable_ifcfg_rh"], enable_ifcfg_rh=no)
AS_IF([test -z "$enable_ifupdown"], enable_ifupdown=no)
# Create automake conditionals
AM_CONDITIONAL(CONFIG_PLUGIN_IFCFG_RH, test "$enable_ifcfg_rh" = "yes")
AM_CONDITIONAL(CONFIG_PLUGIN_IFUPDOWN, test "$enable_ifupdown" = "yes")

AC_ARG_WITH(config-plugins-default,
            AS_HELP_STRING([--with-config-plugins-default=PLUGINS],
                           [Default configuration option for main.plugins setting, used as fallback if the configuration option is unset]),
            [config_plugins_default="$withval"], [config_plugins_default=""])
if test -z "$config_plugins_default" -o "$config_plugins_default" = no; then
	config_plugins_default=''
	test "$enable_ifcfg_rh" = "yes"           && config_plugins_default="$config_plugins_default,ifcfg-rh"
	test "$enable_ifupdown" = "yes"           && config_plugins_default="$config_plugins_default,ifupdown"
	config_plugins_default="${config_plugins_default#,}"
fi

test "$enable_ifcfg_rh" = "yes"           && distro_plugins="$distro_plugins,ifcfg-rh"
test "$enable_ifupdown" = "yes"           && distro_plugins="$distro_plugins,ifupdown"
distro_plugins="${distro_plugins#,}"

AC_DEFINE_UNQUOTED(NM_CONFIG_DEFAULT_MAIN_PLUGINS, "$config_plugins_default", [Default configuration option for main.plugins setting])

if test "$enable_ifcfg_rh" = "yes"; then
	DISTRO_NETWORK_SERVICE=network.service
fi
AC_SUBST(DISTRO_NETWORK_SERVICE)

# Code coverage
GNOME_CODE_COVERAGE

dnl
dnl Distribution version string
dnl
AC_ARG_WITH(dist-version,
            AS_HELP_STRING([--with-dist-version=<NM-distribution-version>],
                           [Define the NM''s distribution version string]),
            ac_distver=$withval, ac_distver=$NM_VERSION)
AC_DEFINE_UNQUOTED(NM_DIST_VERSION, "$ac_distver", [Define the distribution version string])
AC_SUBST(NM_DIST_VERSION, "$ac_distver")

AC_ARG_ENABLE(wifi, AS_HELP_STRING([--enable-wifi], [enable Wi-Fi support]))
if test "${enable_wifi}" != "no"; then
	enable_wifi='yes'
fi
AM_CONDITIONAL(WITH_WIFI, test "${enable_wifi}" = "yes")

dnl
dnl Default to using WEXT but allow it to be disabled
dnl
AC_ARG_WITH(wext,
            AS_HELP_STRING([--with-wext=yes],
                           [Enable or disable Linux Wireless Extensions]),
            ac_with_wext=$withval, ac_with_wext="$enable_wifi")
if test "$ac_with_wext" != 'no'; then
	ac_with_wext='yes'
fi
if test x"$ac_with_wext" = x"yes"; then
	if test "$enable_wifi" != "yes"; then
		AC_MSG_ERROR(Enabling WEXT support and disabling Wi-Fi makes no sense)
	fi
	AC_DEFINE(HAVE_WEXT, 1, [Define if you have Linux Wireless Extensions support])
else
	AC_DEFINE(HAVE_WEXT, 0, [Define if you have Linux Wireless Extensions support])
fi
AM_CONDITIONAL(WITH_WEXT, test x"${ac_with_wext}" = x"yes")

dnl
dnl Default to using wpa_supplicant but allow IWD as wifi backend
dnl
AC_ARG_WITH(iwd,
            AS_HELP_STRING([--with-iwd=yes],
                           [Support IWD as wifi-backend in addition to wpa_supplicant (experimental)]),
            ac_with_iwd=$withval, ac_with_iwd="no")
if test "$ac_with_iwd" != 'no'; then
	ac_with_iwd='yes'
fi
if test x"$ac_with_iwd" = x"yes"; then
	if test "$enable_wifi" != "yes"; then
		AC_MSG_ERROR(Enabling IWD support and disabling Wi-Fi makes no sense)
	fi
	AC_DEFINE(WITH_IWD, 1, [Define to compile with the IWD wifi-backend])
else
	AC_DEFINE(WITH_IWD, 0, [Define to compile without the IWD wifi-backend])
fi
AM_CONDITIONAL(WITH_IWD, test x"${ac_with_iwd}" = x"yes")

dnl
dnl Checks for libdl - on certain platforms its part of libc
dnl
AC_SEARCH_LIBS([dlopen], [dl dld],
	[test "$ac_cv_search_dlopen" = "none required" || AC_SUBST([DL_LIBS], "$ac_cv_search_dlopen"]),
	[])

PKG_CHECK_MODULES(GLIB, [gio-unix-2.0 >= 2.37.6 gmodule-2.0],
                  [AC_SUBST(LOG_DRIVER, '$(top_srcdir)/build-aux/tap-driver.sh')
                   AC_SUBST(AM_TESTS_FD_REDIRECT, '--tap')],
                  [PKG_CHECK_MODULES(GLIB, gio-unix-2.0 >= 2.40 gmodule-2.0)
                   AC_SUBST(LOG_DRIVER, '$(top_srcdir)/build-aux/test-driver')])

GLIB_CFLAGS="$GLIB_CFLAGS -DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_40 -DGLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_40"

AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

GOBJECT_INTROSPECTION_CHECK([0.9.6])

PKG_CHECK_MODULES([LIBUDEV], [libudev >= 175])

# Qt4
PKG_CHECK_MODULES(QT, [QtCore >= 4 QtDBus QtNetwork], [have_qt=yes],[have_qt=no])
AC_ARG_ENABLE(qt,
              AS_HELP_STRING([--enable-qt], [enable Qt examples]),
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

AC_ARG_WITH(udev-dir,
            AS_HELP_STRING([--with-udev-dir=DIR],
                           [Absolute path of the udev base directory. Set to 'no' not to install the udev rules]),
            [], [with_udev_dir="yes"])
if (test "$with_udev_dir" != 'no'); then
	if (test "$with_udev_dir" != 'yes' && printf '%s' "$with_udev_dir" | grep -v -q '^/'); then
		AC_MSG_ERROR([--with-udev-dir must be an absolute path or 'yes' or 'no'. Instead it is '$with_udev_dir'])
	fi
	if (test "$with_udev_dir" = 'yes'); then
		with_udev_dir="\$(prefix)/lib/udev"
	fi
	UDEV_DIR="$with_udev_dir"
	AC_SUBST(UDEV_DIR)
fi
AM_CONDITIONAL(WITH_UDEV_DIR, test "$with_udev_dir" != 'no')

# systemd unit support
AC_ARG_WITH([systemdsystemunitdir],
            AS_HELP_STRING([--with-systemdsystemunitdir=DIR],
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

PKG_CHECK_MODULES(SYSTEMD_200, [systemd >= 200], [have_systemd_200=yes], [have_systemd_200=no])
AM_CONDITIONAL(HAVE_SYSTEMD_200, test "${have_systemd_200}" = "yes")

# Hostname persist mode
AC_ARG_WITH(hostname-persist,
            AS_HELP_STRING([--with-hostname-persist=default|suse|gentoo|slackware],
                           [Hostname persist method]))

AS_IF([test "$with_hostname_persist" = "suse"], hostname_persist=suse)
AS_IF([test "$with_hostname_persist" = "gentoo"], hostname_persist=gentoo)
AS_IF([test "$with_hostname_persist" = "slackware"], hostname_persist=slackware)
AS_IF([test "$with_hostname_persist" = "default"], hostname_persist=default)
# if the method was not explicitly set, try to guess it from the enabled plugins
AS_IF([test -z "$hostname_persist" -a -f /etc/SuSE-release], hostname_persist=suse)
AS_IF([test -z "$hostname_persist" -a -f /etc/gentoo-release], hostname_persist=gentoo)
AS_IF([test -z "$hostname_persist" -a -f /etc/slackware-version], hostname_persist=slackware)
AS_IF([test -z "$hostname_persist"], hostname_persist=default)

if test "$hostname_persist" = suse; then
	AC_DEFINE(HOSTNAME_PERSIST_SUSE, 1, [Enable SuSE hostname persist method])
elif test "$hostname_persist" = gentoo; then
	AC_DEFINE(HOSTNAME_PERSIST_GENTOO, 1, [Enable Gentoo hostname persist method])
elif test "$hostname_persist" = slackware; then
	AC_DEFINE(HOSTNAME_PERSIST_SLACKWARE, 1, [Enable Slackware hostname persist method])
fi

PKG_CHECK_MODULES(LIBSYSTEMD, [libsystemd >= 209],
                  [AC_DEFINE([HAVE_LIBSYSTEMD], 1, [Define to 1 if libsystemd is available])],
                  [AC_DEFINE([HAVE_LIBSYSTEMD], 0, [Define to 1 if libsystemd is available])])

AC_ARG_WITH(systemd-journal,
            AS_HELP_STRING([--with-systemd-journal=yes|no],
                           [Use systemd journal for logging]))
have_systemd_journal=no
if test "$with_systemd_journal" != "no"; then
	PKG_CHECK_MODULES(SYSTEMD_JOURNAL, [libsystemd >= 209], [have_systemd_journal=yes],
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

AC_ARG_WITH(config-logging-backend-default,
            AS_HELP_STRING([--with-config-logging-backend-default=backend],
                           [Default value for logging.backend]),
            nm_config_logging_backend_default="$withval",
            nm_config_logging_backend_default="")

if test "$nm_config_logging_backend_default" != 'syslog' \
     -a "$nm_config_logging_backend_default" != 'journal'; then
	# unknown backend. Reset to default. Silently accept the invalid value to
	# be future proof.
	nm_config_logging_backend_default=''
fi
if test "$nm_config_logging_backend_default" = ""; then
	if test "$have_systemd_journal" = "yes"; then
		nm_config_logging_backend_default='journal'
	else
		nm_config_logging_backend_default='syslog'
	fi
fi
AC_DEFINE_UNQUOTED(NM_CONFIG_DEFAULT_LOGGING_BACKEND, "$nm_config_logging_backend_default", [Default configuration option for logging.backend])
NM_CONFIG_DEFAULT_LOGGING_BACKEND_TEXT="$nm_config_logging_backend_default"
AC_SUBST(NM_CONFIG_DEFAULT_LOGGING_BACKEND_TEXT)

# Session tracking support
AC_ARG_WITH(systemd-logind,
            AS_HELP_STRING([--with-systemd-logind=yes|no],
                           [Support systemd session tracking]))
AC_ARG_WITH(consolekit,
            AS_HELP_STRING([--with-consolekit=yes|no],
                           [Support consolekit session tracking]))
AC_ARG_WITH(session-tracking,
            AS_HELP_STRING([--with-session-tracking=systemd|elogind|consolekit|no],
                           [Compatibility option to choose one session tracking module]))
# backwards compatibility
AS_IF([test "$with_session_tracking" = "ck"], [use_consolekit="yes" use_systemd_logind="no" use_elogind="no"])
AS_IF([test "$with_session_tracking" = "consolekit"], [use_consolekit="yes" use_systemd_logind="no" use_elogind="no"])
AS_IF([test "$with_session_tracking" = "systemd"], [use_consolekit="no" use_systemd_logind="yes" use_elogind="no"])
AS_IF([test "$with_session_tracking" = "elogind"], [use_consolekit="no" use_systemd_logind="no" use_elogind="yes"])
AS_IF([test "$with_session_tracking" = "no"], [use_consolekit="no" use_systemd_logind="no" use_elogind="no"])
AS_IF([test "$with_session_tracking" = "none"], [use_consolekit="no" use_systemd_logind="no" use_elogind="no"])
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
else
	AC_DEFINE([SESSION_TRACKING_SYSTEMD], 0, [Define to 1 if libsystemd-login is available])
fi

if test "$use_elogind" = "yes" -a "$have_systemd_logind" = "yes"; then
	AC_MSG_ERROR([Cannot enable systemd-logind together with elogind.])
fi
if test "$use_elogind" = "yes"; then
	PKG_CHECK_MODULES(SYSTEMD_LOGIN, [libelogind], [have_elogind=yes], [PKG_CHECK_MODULES(SYSTEMD_LOGIN, [libelogind], [have_elogind=yes], [have_elogind=no])])
else
	have_elogind=no
fi
if test "$use_elogind" = "yes" -a "$have_elogind" = "no"; then
	AC_MSG_ERROR([You must have libelogind installed to build with elogind support.])
fi
if test "$have_elogind" = "yes"; then
	AC_DEFINE([SESSION_TRACKING_ELOGIND], 1, [Define to 1 if libelogin is available])
	session_tracking="$session_tracking, elogind"
else
	AC_DEFINE([SESSION_TRACKING_ELOGIND], 0, [Define to 1 if libelogin is available])
fi

if test "$use_consolekit" = "yes"; then
	AC_DEFINE([SESSION_TRACKING_CONSOLEKIT], 1, [Define to 1 if ConsoleKit is available])
	session_tracking="$session_tracking, consolekit"
else
	AC_DEFINE([SESSION_TRACKING_CONSOLEKIT], 0, [Define to 1 if ConsoleKit is available])
fi
session_tracking="$(printf '%s' "${session_tracking}" | sed 's/^, //')"

AC_ARG_WITH(suspend-resume,
            AS_HELP_STRING([--with-suspend-resume=upower|systemd|elogind|consolekit],
                           [Build NetworkManager with specific suspend/resume support]))
if test "z$with_suspend_resume" = "z"; then
	PKG_CHECK_EXISTS([libsystemd >= 209], [have_systemd_inhibit=yes],
	                 [PKG_CHECK_EXISTS([libsystemd-login >= 183], [have_systemd_inhibit=yes], [have_systemd_inhibit=no])])
	if test "z${have_systemd_inhibit}" = "zyes"; then
		# Use systemd if it's new enough
		with_suspend_resume="systemd"
	else
		PKG_CHECK_EXISTS([libelogind >= 219], [have_elogind_inhibit=yes],
		                 [PKG_CHECK_EXISTS([libelogind >= 219], [have_elogind_inhibit=yes], [have_elogind_inhibit=no])])
		if test "z${have_elogind_inhibit}" = "zyes"; then
			# Use elogind if it's new enough
			with_suspend_resume="elogind"
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
fi

case $with_suspend_resume in
	upower)
		AC_DEFINE([SUSPEND_RESUME_UPOWER], 1, [Define to 1 to use UPower suspend api])
		;;
	systemd)
		PKG_CHECK_MODULES(SYSTEMD_INHIBIT, [libsystemd >= 209],,
		                  [PKG_CHECK_MODULES(SYSTEMD_INHIBIT, [libsystemd-login >= 183])])
		AC_DEFINE([SUSPEND_RESUME_SYSTEMD], 1, [Define to 1 to use systemd suspend api])
		;;
	elogind)
		PKG_CHECK_MODULES(ELOGIND_INHIBIT, [libelogind >= 219],,
		                  [PKG_CHECK_MODULES(ELOGIND_INHIBIT, [libelogind >= 219])])
		AC_DEFINE([SUSPEND_RESUME_ELOGIND], 1, [Define to 1 to use elogind suspend api])
		;;
	consolekit)
		AC_DEFINE([SUSPEND_RESUME_CONSOLEKIT], 1, [Define to 1 to use ConsoleKit2 suspend api])
		;;
	*)
		AC_MSG_ERROR(--with-suspend-resume must be one of [upower, systemd, elogind, consolekit])
		;;
esac

# eBPF support
AC_ARG_WITH(ebpf,
            AS_HELP_STRING([--with-ebpf=yes|no|auto], [Build with eBPF support [default=auto]]),
            [], [with_ebpf=auto])
# 'auto' means 'false' because there are still some issues.
if test "$with_ebpf" = "yes" ; then
	AC_CHECK_HEADER(linux/bpf.h, [have_ebpf=yes], [have_ebpf=no])
else
	have_ebpf=no
fi
if test "$with_ebpf" = "yes" -a "$have_ebpf" = "no"; then
	AC_MSG_ERROR([--with-ebpf=yes requires eBPF kernel header])
fi
AM_CONDITIONAL(WITH_EBPF, test "${have_ebpf}" = "yes")

# SELinux support
AC_ARG_WITH(selinux,
            AS_HELP_STRING([--with-selinux=yes|no|auto], [Build with SELinux [default=auto]]),
            [], [with_selinux=auto])
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
AC_ARG_WITH(libaudit, AS_HELP_STRING([--with-libaudit=yes|yes-disabled-by-default|no|auto], [Build with audit daemon support [default=auto]. yes-disabled-by-default enables support, but disables it unless explicitly configured via NetworkManager.conf]),,[with_libaudit=auto])
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
		AC_DEFINE(NM_CONFIG_DEFAULT_LOGGING_AUDIT, "false", [The default value of the logging.audit configuration option])
		NM_CONFIG_DEFAULT_LOGGING_AUDIT_TEXT='false'
	else
		AC_DEFINE(NM_CONFIG_DEFAULT_LOGGING_AUDIT, "true",  [The default value of the logging.audit configuration option])
		NM_CONFIG_DEFAULT_LOGGING_AUDIT_TEXT='true'
	fi
else
	AC_DEFINE(HAVE_LIBAUDIT, 0, [Define if you have libaudit support])
	AC_DEFINE(NM_CONFIG_DEFAULT_LOGGING_AUDIT, "false", [The default value of the logging.audit configuration option])
	NM_CONFIG_DEFAULT_LOGGING_AUDIT_TEXT='false'
fi
AC_SUBST(NM_CONFIG_DEFAULT_LOGGING_AUDIT_TEXT)

# uuid library
PKG_CHECK_MODULES(UUID, uuid)

# Teamd control checks

PKG_CHECK_MODULES(JANSSON, [jansson >= 2.5], [have_jansson=yes], [have_jansson=no])
if test "$have_jansson" = "yes"; then
	AC_DEFINE(WITH_JANSSON, 1, [Define if JANSSON is enabled])

	AC_CHECK_TOOLS(READELF, [eu-readelf readelf])
	JANSSON_LIBDIR=`$PKG_CONFIG --variable=libdir jansson`
	JANSSON_SONAME=`$READELF -d $JANSSON_LIBDIR/libjansson.so |sed -n 's/.*SONAME.*\[[\([^]]*\)]]/\1/p'`

	if test "$JANSSON_SONAME" = ""; then
		AC_MSG_ERROR(Unable to locate the Jansson library)
	fi
	AC_DEFINE_UNQUOTED(JANSSON_SONAME, "$JANSSON_SONAME", [Define to path to the Jansson shared library])
else
	AC_DEFINE(WITH_JANSSON, 0, [Define if JANSSON is enabled])
fi
AM_CONDITIONAL(WITH_JANSSON, test "${have_jansson}" = "yes")

PKG_CHECK_MODULES(LIBTEAMDCTL, [libteamdctl >= 1.9], [have_teamdctl=yes],[have_teamdctl=no])
if test "$have_jansson" = "yes" -a "$have_teamdctl" = "yes"; then
	have_team_prereq=yes
else
	have_team_prereq=no
fi

AC_ARG_ENABLE(teamdctl,
              AS_HELP_STRING([--enable-teamdctl], [enable Teamd control support]),
              [enable_teamdctl=${enableval}], [enable_teamdctl=${have_team_prereq}])
if (test "${enable_teamdctl}" = "yes"); then
	if test "$have_teamdctl" = "no"; then
		AC_MSG_ERROR(Libteamdctl is required for team support)
	fi
	if test "$have_jansson" = "no"; then
		AC_MSG_ERROR(Jansson is required for team support)
	fi
	# temporary bug workaround
	LIBTEAMDCTL_CFLAGS=`echo $LIBTEAMDCTL_CFLAGS | sed -e 's:/teamdctl.h::'`
fi
AM_CONDITIONAL(WITH_TEAMDCTL, test "${enable_teamdctl}" = "yes")

# Jansson for team configuration validation
AC_ARG_ENABLE(json-validation,
              AS_HELP_STRING([--enable-json-validation], [Enable JSON validation in libnm]),
              [enable_json_validation=${enableval}],
              [enable_json_validation=${have_jansson}])
if (test "${enable_json_validation}" == "no"); then
	AC_DEFINE(WITH_JSON_VALIDATION, 0, [Define if JSON validation in libnm is enabled])
else
	if test "$have_jansson" = "no"; then
		AC_MSG_ERROR([jansson is needed for team configuration validation. Use --disable-json-validation to build without it.])
	fi
		AC_DEFINE(WITH_JSON_VALIDATION, 1, [Define if JSON validation in libnm is enabled])
fi
AM_CONDITIONAL(WITH_JSON_VALIDATION, test "${enable_json_validation}" != "no")

# we usually compile with polkit support. --enable-polkit=yes|no only sets the
# default configuration for main.auth-polkit. User can always enable/disable polkit
# authorization via config.
AC_ARG_ENABLE(polkit,
              AS_HELP_STRING([--enable-polkit=yes|no],
                             [set default value for auth-polkit configuration option. This value can be overwritten by NM configuration. 'disabled' is an alias for 'no']),
              [enable_polkit=${enableval}], [enable_polkit=yes])
if (test "${enable_polkit}" != "no" -a "${enable_polkit}" != "disabled"); then
	enable_polkit=true
	AC_DEFINE(NM_CONFIG_DEFAULT_MAIN_AUTH_POLKIT, "true", [The default value of the auth-polkit configuration option])
	AC_SUBST(NM_CONFIG_DEFAULT_MAIN_AUTH_POLKIT_TEXT, true)
else
	enable_polkit=false
	AC_DEFINE(NM_CONFIG_DEFAULT_MAIN_AUTH_POLKIT, "false", [The default value of the auth-polkit configuration option])
	AC_SUBST(NM_CONFIG_DEFAULT_MAIN_AUTH_POLKIT_TEXT, false)
fi

PKG_CHECK_MODULES(POLKIT, [polkit-agent-1 >= 0.97], [have_pk_agent=yes],[have_pk_agent=no])
AC_ARG_ENABLE(polkit-agent,
              AS_HELP_STRING([--enable-polkit-agent], [enable polkit agent for clients]),
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

AC_ARG_ENABLE(modify-system, AS_HELP_STRING([--enable-modify-system], [Allow users to modify system connections]))
if test "${enable_modify_system}" = "yes"; then
	NM_MODIFY_SYSTEM_POLICY="yes"
else
	NM_MODIFY_SYSTEM_POLICY="auth_admin_keep"
fi
AC_SUBST(NM_MODIFY_SYSTEM_POLICY)

PKG_CHECK_MODULES(GNUTLS, [gnutls >= 2.12], [have_crypto_gnutls=yes], [have_crypto_gnutls=no])
PKG_CHECK_MODULES(NSS, [nss], [have_crypto_nss=yes], [have_crypto_nss=yes])
if test "${have_crypto_nss}" = "yes"; then
	# Work around a pkg-config bug (fdo #29801) where exists != usable
	FOO=`$PKG_CONFIG --cflags --libs nss`
	if test x"$?" != "x0"; then
		have_crypto_nss=no
	fi
fi
AM_CONDITIONAL(HAVE_CRYPTO_GNUTLS, test "${have_crypto_gnutls}" = 'yes')
AM_CONDITIONAL(HAVE_CRYPTO_NSS, test "${have_crypto_nss}" = 'yes')

AC_ARG_WITH(crypto,
            AS_HELP_STRING([--with-crypto=nss|gnutls],
                           [Cryptography library to use for certificate and key operations]),
            with_crypto=$withval,
            with_crypto=nss)
if test "$with_crypto" = 'nss'; then
	if test "${have_crypto_nss}" != "yes"; then
		AC_MSG_ERROR([No usable NSS found for --with-crypto=nss])
	fi
elif test "$with_crypto" = 'gnutls'; then
	if test "${have_crypto_gnutls}" != "yes"; then
		AC_MSG_ERROR([No usable gnutls found for --with-crypto=gnutls])
	fi
else
	AC_MSG_ERROR([Please choose either 'nss' or 'gnutls' for certificate and crypto operations])
fi
AM_CONDITIONAL(WITH_NSS, test "$with_crypto" = 'nss')
AM_CONDITIONAL(WITH_GNUTLS, test "$with_crypto" = 'gnutls')

GLIB_MAKEFILE='$(top_srcdir)/Makefile.glib'
AC_SUBST(GLIB_MAKEFILE)
GLIB_MKENUMS=`$PKG_CONFIG --variable=glib_mkenums glib-2.0`
AC_SUBST(GLIB_MKENUMS)

AC_ARG_WITH(dbus-sys-dir,
            AS_HELP_STRING([--with-dbus-sys-dir=DIR], [where D-BUS system.d directory is]))

if test -n "$with_dbus_sys_dir" ; then
	DBUS_SYS_DIR="$with_dbus_sys_dir"
else
	DBUS_SYS_DIR="${sysconfdir}/dbus-1/system.d"
fi
AC_SUBST(DBUS_SYS_DIR)

# pppd
AC_ARG_ENABLE(ppp,
              AS_HELP_STRING([--enable-ppp], [enable PPP/PPPoE support]),
              [enable_ppp=${enableval}], [enable_ppp=yes])
if (test "${enable_ppp}" = "yes"); then
	AC_CHECK_HEADERS(pppd/pppd.h,,
	                 AC_MSG_ERROR("couldn't find pppd.h. pppd development headers are required."))

	AC_DEFINE(WITH_PPP, 1, [Define if you have PPP support])
else
	AC_DEFINE(WITH_PPP, 0, [Define if you have PPP support])
fi
AM_CONDITIONAL(WITH_PPP, test "${enable_ppp}" = "yes")

AC_ARG_WITH([pppd-plugin-dir],
            AS_HELP_STRING([--with-pppd-plugin-dir=DIR], [path to the pppd plugins directory]))

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
AC_ARG_WITH(modem-manager-1,
            AS_HELP_STRING([--with-modem-manager-1],
                           [Enable new ModemManager1 interface support]),
            [], [with_modem_manager_1=auto])
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
AM_CONDITIONAL(WITH_MODEM_MANAGER_1, test "${with_modem_manager_1}" = "yes")

# Bluez5 DUN support
PKG_CHECK_MODULES(BLUEZ5, [bluez >= 5], [have_bluez5=yes],[have_bluez5=no])
AC_ARG_ENABLE(bluez5-dun,
              AS_HELP_STRING([--enable-bluez5-dun], [enable Bluez5 DUN support]),
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

# OFONO
AC_ARG_WITH(ofono,
            AS_HELP_STRING([--with-ofono], [Enable oFono support (experimental)]),
            [], [with_ofono=no])
if (test "${with_ofono}" = "yes"); then
	AC_DEFINE(WITH_OFONO, 1, [Define if you have oFono support (experimental)])
else
	AC_DEFINE(WITH_OFONO, 0, [Define if you have oFono support (experimental)])
fi
AM_CONDITIONAL(WITH_OFONO, test "${with_ofono}" = "yes")

# DHCP client support with dhcpcanon
AC_ARG_WITH([dhcpcanon],
            AS_HELP_STRING([--with-dhcpcanon=yes|no|path], [Enable dhcpcanon support (experimental)]))
if test "$with_dhcpcanon" != "no"; then
    with_dhcpcanon_="$with_dhcpcanon"
    AC_PATH_PROGS(with_dhcpcanon, dhcpcanon, no, /sbin:/usr/sbin:/usr/local/sbin:/usr/bin:/usr/local/bin)
    if test "$with_dhcpcanon" == "no"; then
        if test "$with_dhcpcanon_" == yes; then
            AC_MSG_WARN([dhcpcanon not found, assume path /sbin/dhcpcanon])
            with_dhcpcanon=/sbin/dhcpcanon
        fi
    fi
fi
if test "$with_dhcpcanon" != "no"; then
    AC_DEFINE(WITH_DHCPCANON, 1, [Define if you have dhcpcanon])
    AC_DEFINE_UNQUOTED(DHCPCANON_PATH, "$with_dhcpcanon", [Define path to dhcpcanon])
else
    AC_DEFINE(WITH_DHCPCANON, 0, [Define if you have dhcpcanon])
fi

# Open vSwitch integration
AC_ARG_ENABLE(ovs, AS_HELP_STRING([--enable-ovs], [enable Open vSwitch support]))
if test "${enable_ovs}" != "no"; then
	enable_ovs='yes'
	if test "$have_jansson" = "no"; then
		AC_MSG_ERROR(Jansson is required for ovs support)
	fi
fi
AM_CONDITIONAL(WITH_OPENVSWITCH, test "${enable_ovs}" = "yes")

# DHCP client support
AC_ARG_WITH([dhclient],
            AS_HELP_STRING([--with-dhclient=yes|no|path], [Enable dhclient support]))
if test "$with_dhclient" != "no"; then
	with_dhclient_="$with_dhclient"
	AC_PATH_PROGS(with_dhclient, dhclient, no, /sbin:/usr/sbin:/usr/local/sbin)
	if test "$with_dhclient" == "no"; then
		if test "$with_dhclient_" == yes; then
			AC_MSG_WARN([dhclient not found, assume path /usr/sbin/dhclient])
			with_dhclient=/usr/sbin/dhclient
		fi
	fi
fi
if test "$with_dhclient" != "no"; then
	AC_DEFINE(WITH_DHCLIENT, 1, [Define if you have dhclient])
	AC_DEFINE_UNQUOTED(DHCLIENT_PATH, "$with_dhclient", [Define path to dhclient])
else
	AC_DEFINE(WITH_DHCLIENT, 0, [Define if you have dhclient])
fi

AC_ARG_WITH([dhcpcd],
            AS_HELP_STRING([--with-dhcpcd=yes|no|path], [Enable dhcpcd 4.x support]))
if test "$with_dhcpcd" != "no"; then
	with_dhcpcd_="$with_dhcpcd"
	AC_PATH_PROGS(with_dhcpcd, dhcpcd, no, /sbin:/usr/sbin:/usr/local/sbin)
	if test "$with_dhcpcd" == "no"; then
		if test "$with_dhcpcd_" == yes; then
			AC_MSG_WARN([dhcpcd not found, assume path /usr/sbin/dhcpcd])
			with_dhcpcd=/usr/sbin/dhcpcd
		fi
	fi
fi
if test "$with_dhcpcd" != "no"; then
	AC_DEFINE(WITH_DHCPCD, 1, [Define if you have dhcpcd])
	AC_DEFINE_UNQUOTED(DHCPCD_PATH, "$with_dhcpcd", [Define path to dhcpcd])
else
	AC_DEFINE(WITH_DHCPCD, 0, [Define if you have dhcpcd])
fi

AC_ARG_WITH(config-dhcp-default,
            AS_HELP_STRING([--with-config-dhcp-default=dhclient|dhcpcd|internal],
                           [Default configuration option for main.dhcp setting, used as fallback if the configuration option is unset [default=internal]]),
            [config_dhcp_default="$withval"], [config_dhcp_default=""])
if test "$config_dhcp_default" = yes -o "$config_dhcp_default" = no -o -z "$config_dhcp_default"; then
	config_dhcp_default='internal'
fi
AC_DEFINE_UNQUOTED(NM_CONFIG_DEFAULT_MAIN_DHCP, "$config_dhcp_default", [Default configuration option for main.dhcp setting])
AC_SUBST(NM_CONFIG_DEFAULT_MAIN_DHCP, $config_dhcp_default)

AC_ARG_WITH(resolvconf, AS_HELP_STRING([--with-resolvconf=yes|no|path], [Enable resolvconf support]))
AC_ARG_WITH(netconfig, AS_HELP_STRING([--with-netconfig=yes|no], [Enable SUSE netconfig support]))
AC_ARG_WITH(config-dns-rc-manager-default, AS_HELP_STRING([--with-config-dns-rc-manager-default=symlink|file|netconfig|resolvconf], [Configure default value for main.rc-manager setting]), [config_dns_rc_manager_default=$withval])
if test "$config_dns_rc_manager_default" != "" -a \
        "$config_dns_rc_manager_default" != file -a \
        "$config_dns_rc_manager_default" != symlink -a \
        "$config_dns_rc_manager_default" != netconfig -a \
        "$config_dns_rc_manager_default" != resolvconf; then
	AC_MSG_WARN([Unknown --with-config-dns-rc-manager-default=$config_dns_rc_manager_default setting.])
	config_dns_rc_manager_default=
fi
# Use netconfig by default on SUSE
AS_IF([test -z "$with_netconfig" -a -f /etc/SuSE-release], with_netconfig=yes)
# Otherwise default to "no"
AS_IF([test -z "$with_resolvconf"], with_resolvconf=no)
AS_IF([test -z "$with_netconfig"], with_netconfig=no)

if test "$with_resolvconf" = "yes"; then
	AC_PATH_PROGS(with_resolvconf, resolvconf, 'yes', /sbin:/usr/sbin:/usr/local/sbin)
	if test "$with_resolvconf" = "yes"; then
		AC_MSG_ERROR(cannot find resolvconf in path. Set the path explicitly via --with-resolvconf=PATH.)
	fi
fi
if test "$with_resolvconf" != "no"; then
	AS_IF([test -z "$config_dns_rc_manager_default"], config_dns_rc_manager_default=resolvconf)
fi

if test "$with_netconfig" = "yes"; then
	AC_PATH_PROGS(with_netconfig, netconfig, yes, /sbin:/usr/sbin:/usr/local/sbin)
	if test "$with_netconfig" = "yes"; then
		AC_MSG_ERROR(cannot find netconfig in path. Set the path explicitly via --with-netconfig=PATH.)
	fi
fi
if test "$with_netconfig" != "no"; then
	AS_IF([test -z "$config_dns_rc_manager_default"], config_dns_rc_manager_default=netconfig)
fi

AS_IF([test -z "$config_dns_rc_manager_default"], config_dns_rc_manager_default=symlink)

if test "$with_resolvconf" != "no"; then
	AC_DEFINE_UNQUOTED(RESOLVCONF_PATH, "$with_resolvconf", [Path to resolvconf])
fi
if test "$with_netconfig" != "no"; then
	AC_DEFINE_UNQUOTED(NETCONFIG_PATH, "$with_netconfig", [Path to netconfig])
fi
AC_DEFINE_UNQUOTED(NM_CONFIG_DEFAULT_MAIN_RC_MANAGER, "$config_dns_rc_manager_default", [Default value for main.rc-manager setting (--with-config-dns-rc-manager-default)])
AC_SUBST(NM_CONFIG_DEFAULT_MAIN_RC_MANAGER, $config_dns_rc_manager_default)

# iptables path
AC_ARG_WITH(iptables,
            AS_HELP_STRING([--with-iptables=/path/to/iptables], [path to iptables]))
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
AC_ARG_WITH(dnsmasq,
            AS_HELP_STRING([--with-dnsmasq=/path/to/dnsmasq], [path to dnsmasq]))
if test "x${with_dnsmasq}" = x; then
	AC_PATH_PROG(DNSMASQ_PATH, dnsmasq, [], $PATH:/sbin:/usr/sbin)
else
	DNSMASQ_PATH="$with_dnsmasq"
fi
AC_DEFINE_UNQUOTED(DNSMASQ_PATH, "$DNSMASQ_PATH", [Define to path of dnsmasq binary])
AC_SUBST(DNSMASQ_PATH)

# dnssec-trigger-script path
AC_ARG_WITH(dnssec_trigger,
            AS_HELP_STRING([--with-dnssec-trigger=/path/to/dnssec-trigger-script], [path to unbound dnssec-trigger-script]))
if test "x${with_dnssec_trigger}" = x; then
	AC_PATH_PROG(DNSSEC_TRIGGER_PATH, dnssec-trigger-script, /usr/libexec/dnssec-trigger-script,
	             /usr/local/libexec:/usr/local/lib:/usr/local/lib/dnssec-trigger:/usr/libexec:/usr/lib:/usr/lib/dnssec-trigger)
else
	DNSSEC_TRIGGER_PATH="$with_dnssec_trigger"
fi
AC_DEFINE_UNQUOTED(DNSSEC_TRIGGER_PATH, "$DNSSEC_TRIGGER_PATH", [Define to path of unbound dnssec-trigger-script])
AC_SUBST(DNSSEC_TRIGGER_PATH)

# system CA certificates path
AC_ARG_WITH(system-ca-path,
            AS_HELP_STRING([--with-system-ca-path=/path/to/ssl/certs], [path to system CA certificates]))
if test "x${with_system_ca_path}" = x; then
	SYSTEM_CA_PATH=/etc/ssl/certs
else
	SYSTEM_CA_PATH="$with_system_ca_path"
fi
AC_DEFINE_UNQUOTED(SYSTEM_CA_PATH, "$SYSTEM_CA_PATH", [Define to path to system CA certificates])
AC_SUBST(SYSTEM_CA_PATH)

AC_ARG_WITH(kernel-firmware-dir,
            AS_HELP_STRING([--with-kernel-firmware-dir=DIR], [where kernel firmware directory is [default=/lib/firmware]]))
if test -n "$with_kernel_firmware_dir" ; then
	KERNEL_FIRMWARE_DIR="$with_kernel_firmware_dir"
else
	KERNEL_FIRMWARE_DIR="/lib/firmware"
fi
AC_DEFINE_UNQUOTED(KERNEL_FIRMWARE_DIR, "$KERNEL_FIRMWARE_DIR", [Define to path of the kernel firmware directory])
AC_SUBST(KERNEL_FIRMWARE_DIR)

PKG_CHECK_MODULES(LIBPSL, [libpsl >= 0.1], [have_libpsl=yes],[have_libpsl=no])
AC_ARG_WITH(libpsl,
            AS_HELP_STRING([--with-libpsl=yes|no], [Link against libpsl]),
            [], [with_libpsl=${have_libpsl}])
if test "$with_libpsl" != "no"; then
	if test "$have_libpsl" != "yes"; then
		AC_MSG_ERROR(libpsl library not found)
	fi
	with_libpsl='yes'
	AC_DEFINE(WITH_LIBPSL, 1, [Define if you have libpsl])
else
	AC_DEFINE(WITH_LIBPSL, 0, [Define if you have libpsl])
fi
AM_CONDITIONAL(WITH_LIBPSL, test "$with_libpsl" != "no")


AC_ARG_ENABLE(concheck,
              AS_HELP_STRING([--enable-concheck], [enable connectivity checking support]),
              [enable_concheck=${enableval}], [enable_concheck=yes])
if test "${enable_concheck}" = "yes"; then
	PKG_CHECK_MODULES(LIBCURL, [libcurl >= 7.24.0], [have_libcurl=yes], [have_libcurl=no])
	if test "$have_libcurl" != "yes"; then
		AC_MSG_ERROR(--enable-concheck requires libcurl library.)
	fi
	AC_DEFINE(WITH_CONCHECK, 1, [Define if you want connectivity checking support])
else
	enable_concheck=no
	AC_DEFINE(WITH_CONCHECK, 0, [Define if you want connectivity checking support])
fi

PKG_CHECK_MODULES(LIBNDP, [libndp])

AC_ARG_WITH(nmcli,
            AS_HELP_STRING([--with-nmcli=yes|no], [Build nmcli]))
if test "$with_nmcli" != no; then
	AX_LIB_READLINE
	build_nmcli=yes
else
	build_nmcli=no
fi
AM_CONDITIONAL(BUILD_NMCLI, test "$build_nmcli" = yes)

AC_ARG_WITH(nmtui,
            AS_HELP_STRING([--with-nmtui=yes|no], [Build nmtui]))
if test "$with_nmtui" != no; then
	PKG_CHECK_MODULES(NEWT, [libnewt >= 0.52.15], [build_nmtui=yes], [build_nmtui=no])
else
	build_nmtui=no
fi
if test "$with_nmtui" = yes -a "$build_nmtui" = no; then
	AC_MSG_ERROR([You must have libnewt installed to build nmtui.])
fi
AM_CONDITIONAL(BUILD_NMTUI, test "$build_nmtui" = yes)

if test $(( ${NM_MINOR_VERSION} % 2 )) = "1"; then
	# A development version
	more_warnings_default=error
	more_asserts_default=100
	more_logging_default=yes
else
	# A release version
	more_warnings_default=yes
	more_asserts_default=0
	more_logging_default=no
fi

NM_COMPILER_WARNINGS(AM_CFLAGS, ${more_warnings_default})

NM_COMPILER_FLAG(LIBSYSTEMD_NM_CFLAGS, "-Wno-gnu-variable-sized-type-not-at-end")
AC_SUBST(LIBSYSTEMD_NM_CFLAGS)

CC_CHECK_FLAGS_APPEND([with_cflags], [CFLAGS], [\
	-fno-strict-aliasing \
])
AM_CFLAGS="$AM_CFLAGS $with_cflags"

AC_ARG_ENABLE(more-asserts,
              AS_HELP_STRING([--enable-more-asserts],
                             [Enable more assertions for debugging [default=auto]. Deprecated option. Use --with-more-asserts=level]))
if test "${enable_more_asserts}" = "yes"; then
	more_asserts=100
fi
AC_ARG_WITH(more-asserts,
            AS_HELP_STRING([--with-more-asserts=level], [Enable more assertions for debugging (0 = none, 100 = all) [default=auto]]),
            [more_asserts=${with_more_asserts}],
            [])
if test "${more_asserts}" = "no"; then
	more_asserts=0
else
	if test "${more_asserts}" = "yes"; then
		more_asserts=100
	fi
fi
if test "${more_asserts}" = ""; then
	more_asserts=${more_asserts_default}
fi
AC_DEFINE_UNQUOTED(NM_MORE_ASSERTS, $more_asserts, [Define if more asserts are enabled])

AC_ARG_ENABLE(more-logging, AS_HELP_STRING([--enable-more-logging], [Enable more debug logging [default=auto]]))
if test "${enable_more_logging}" = ""; then
	enable_more_logging=${more_logging_default}
fi
if test "${enable_more_logging}" = "yes"; then
	AC_DEFINE(NM_MORE_LOGGING, [1], [Define if more debug logging is enabled])
else
	AC_DEFINE(NM_MORE_LOGGING, [0], [Define if more debug logging is enabled])
fi

NM_LTO
NM_LD_GC

AC_ARG_WITH(address-sanitizer,
            AS_HELP_STRING([--with-address-sanitizer=yes|no|exec], [Enable address sanitizer [default=no]]))
if test "$with_address_sanitizer" = yes -o "$with_address_sanitizer" = "exec"; then
	CC_CHECK_FLAGS_APPEND([asan_cflags], [CFLAGS], [-fsanitize=address])
	AS_IF([test -z "$asan_cflags"],
		[AC_MSG_ERROR([*** -fsanitize=address is not supported])])

	sanitizer_exec_cflags="$sanitizer_exec_cflags -fsanitize=address"
	sanitizer_exec_ldflags="$sanitizer_exec_ldflags -Wc,-fsanitize=address"
	AC_DEFINE(ASAN_BUILD, 1, [Whether NM is built with address sanitizer])

	if test "$with_address_sanitizer" = "yes"; then
		sanitizer_lib_cflags="$sanitizer_lib_cflags -fsanitize=address"
		sanitizer_lib_ldflags="$sanitizer_lib_ldflags -Wc,-fsanitize=address"
		sanitizers="${sanitizers}address "
		asan_options="ASAN_OPTIONS=detect_leaks=0"
	else
		sanitizers="${sanitizers}address(executables-only) "
	fi
fi

AC_ARG_ENABLE(undefined-sanitizer,
              AS_HELP_STRING([--enable-undefined-sanitizer],
                             [Compile with undefined behavior sanitizer [default=no]]))
if (test "${enable_undefined_sanitizer}" = "yes"); then
	CC_CHECK_FLAGS_APPEND([ubsan_cflags], [CFLAGS], [-fsanitize=undefined])
	AS_IF([test -z "$ubsan_cflags"],
	      [AC_MSG_ERROR([*** -fsanitize=undefined is not supported])])

	sanitizer_exec_cflags="$sanitizer_exec_cflags -fsanitize=undefined"
	sanitizer_lib_cflags="$sanitizer_lib_cflags -fsanitize=undefined"
	sanitizer_exec_ldflags="$sanitizer_exec_ldflags -Wc,-fsanitize=undefined"
	sanitizer_lib_ldflags="$sanitizer_lib_ldflags -Wc,-fsanitize=undefined"
	sanitizers="${sanitizers}undefined-behavior "
fi

if test -n "$sanitizers"; then
	sanitizers="${sanitizers% }"
	AC_SUBST(SANITIZER_ENV, ["$asan_options"])
	AC_SUBST(SANITIZER_EXEC_CFLAGS, ["$sanitizer_exec_cflags -DVALGRIND=1 -fno-omit-frame-pointer"])
	AC_SUBST(SANITIZER_LIB_CFLAGS, ["$sanitizer_lib_cflags -DVALGRIND=1 -fno-omit-frame-pointer"])
	AC_SUBST(SANITIZER_EXEC_LDFLAGS, [$sanitizer_exec_ldflags])
	AC_SUBST(SANITIZER_LIB_LDFLAGS, [$sanitizer_lib_ldflags])
fi

AC_MSG_CHECKING([CC support C11 _Generic()])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[int foo(void); int foo() { int a = 0; int b = _Generic (a, int: 4); return b + a; }]],
                                  [[foo();]])],
                  [cc_support_generic=1],
                  [cc_support_generic=0])
AC_MSG_RESULT($cc_support_generic)
AC_DEFINE_UNQUOTED(_NM_CC_SUPPORT_GENERIC, $cc_support_generic, [Define whether the compiler supports C11 _Generic()])

AC_MSG_CHECKING([CC support gcc __auto_type])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[int foo(void); int foo() { int a = 0; __auto_type b = a; return b + a; }]],
                                  [[foo();]])],
                  [cc_support_auto_type=1],
                  [cc_support_auto_type=0])
AC_MSG_RESULT($cc_support_auto_type)
AC_DEFINE_UNQUOTED(_NM_CC_SUPPORT_AUTO_TYPE, $cc_support_auto_type, [Define whether the compiler support gcc __auto_type])

dnl -------------------------
dnl Vala bindings
dnl -------------------------

VAPIGEN_CHECK(0.17.1.24)
AC_CONFIG_COMMANDS([vapi], [$MKDIR_P vapi])

# Tests, utilities and documentation
AC_ARG_ENABLE(tests, AS_HELP_STRING([--enable-tests=root|yes|no], [Build NetworkManager tests [default=yes]]))
AC_ARG_WITH(valgrind,
            AS_HELP_STRING([--with-valgrind=yes|no|path], [Use valgrind to memory-check the tests [default=no]]))
# Fallback to --with-tests
AC_ARG_WITH(tests,
            AS_HELP_STRING([--with-tests], [Build NetworkManager tests (deprecated)]))
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
AC_ARG_WITH(valgrind-suppressions,
            AS_HELP_STRING([--with-valgrind-suppressions=path], [Use specific valgrind suppression file]))
if test "$with_valgrind" == no; then
	with_valgrind_suppressions=
else
	if test  "$with_valgrind_suppressions" == ""; then
		with_valgrind_suppressions='$(top_srcdir)/valgrind.suppressions'
	fi
fi
AC_SUBST(NM_LOG_COMPILER, 'LOG_COMPILER = "$(top_srcdir)/tools/run-nm-test.sh" --called-from-make "$(abs_top_builddir)" "$(LIBTOOL)" "$(with_valgrind)" "'"$with_valgrind_suppressions"'" --launch-dbus=auto')

AM_PATH_PYTHON([], [], [PYTHON=python])
AC_SUBST(PYTHON, [$PYTHON])
AC_DEFINE_UNQUOTED(TEST_NM_PYTHON, "$PYTHON", [Define python path for test binary])

GTK_DOC_CHECK(1.0)

# check if we can build setting property documentation
build_docs=no
if test -n "$INTROSPECTION_MAKEFILE"; then
	# If g-i is installed we know we have python, but we might not have pygobject
	if ! "$PYTHON" -c 'from gi.repository import GObject' >& /dev/null; then
		AC_MSG_ERROR(["--enable-introspection aims to build the settings documentation. This requires GObject introspection for python (pygobject)])
	fi

	AC_PATH_PROG(PERL, perl)
	if test -z "$PERL"; then
		AC_MSG_ERROR([--enable-introspection requires perl])
	fi
	AC_PATH_PROG(XSLTPROC, xsltproc)
	if test -z "$XSLTPROC"; then
		AC_MSG_ERROR([--enable-introspection requires xsltproc])
	fi

	have_introspection=yes
	if test "$enable_gtk_doc" = "yes"; then
		build_docs=yes
	fi
else
	if test "$enable_gtk_doc" = "yes"; then
		# large parts of the documentation require introspection/pygobject to extract
		# the documentation out of the source files. You cannot enable gtk-doc without alone.
		AC_MSG_ERROR(["--enable-gtk-doc requires --enable-introspection"])
	fi
	have_introspection=no
fi

# check for pregenerated manpages and documentation to be installed
use_pregen_docs=no
if test "$build_docs" != "yes" -a \
        -f "$srcdir"/man/NetworkManager.8 -a \
        -f "$srcdir"/man/NetworkManager.conf.5 -a \
        -f "$srcdir"/man/nm-online.1 -a \
        -f "$srcdir"/man/nmcli-examples.7 -a \
        -f "$srcdir"/man/nmcli.1 -a \
        -f "$srcdir"/man/nmtui.1 -a \
        \
        -f "$srcdir"/man/nm-openvswitch.7 -a \
        \
        -f "$srcdir"/man/nm-settings-ifcfg-rh.5 -a \
        -f "$srcdir"/man/nm-settings-keyfile.5 -a \
        -f "$srcdir"/man/nm-settings.5 -a \
        \
        -f "$srcdir"/man/nm-settings.xml -a \
        -f "$srcdir"/man/nm-settings-keyfile.xml -a \
        -f "$srcdir"/man/nm-settings-ifcfg-rh.xml -a \
        \
        -f "$srcdir"/docs/api/settings-spec.xml; then
	use_pregen_docs=yes
fi

AM_CONDITIONAL(BUILD_DOCS, test "$build_docs" = "yes")
AM_CONDITIONAL(HAVE_DOCS, test "$build_docs" = "yes" -o "$use_pregen_docs" = "yes")
AC_SUBST(AM_CFLAGS)

AC_CONFIG_FILES([
Makefile
shared/nm-version-macros.h
libnm/libnm.pc
po/Makefile.in
data/org.freedesktop.NetworkManager.policy.in
docs/api/Makefile
docs/api/version.xml
docs/libnm/Makefile
docs/libnm/version.xml
NetworkManager.pc
])
AC_OUTPUT

# Print build configuration
echo
echo "System paths:"
echo "  prefix: $prefix"
echo "  exec_prefix: $exec_prefix"
echo "  sysconfdir: $sysconfdir"
echo "  localstatedir: $localstatedir"
echo "  runstatedir: $runstatedir"
echo "  datadir: $datadir"
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
if test "${enable_modify_system}" = "yes"; then
	echo "  policykit: main.auth-polkit=${enable_polkit} (permissive modify.system)"
else
	echo "  policykit: main.auth-polkit=${enable_polkit} (restrictive modify.system)"
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
echo "  ppp: $enable_ppp ${PPPD_PATH} plugins:${PPPD_PLUGIN_DIR}"
echo "  modemmanager-1: $with_modem_manager_1"
echo "  ofono: $with_ofono"
echo "  concheck: $enable_concheck"
echo "  libteamdctl: $enable_teamdctl"
echo "  ovs: $enable_ovs"
echo "  nmcli: $build_nmcli"
echo "  nmtui: $build_nmtui"
echo "  iwd: $ac_with_iwd"
echo

echo "Configuration plugins (main.plugins=${config_plugins_default})"
echo "  ifcfg-rh: ${enable_ifcfg_rh}"
echo "  ifupdown: ${enable_ifupdown}"
echo

echo "Handlers for /etc/resolv.conf:"
echo "  resolvconf: ${with_resolvconf}"
echo "  netconfig: ${with_netconfig}"
echo "  config-dns-rc-manager-default: ${config_dns_rc_manager_default}"
echo

echo "DHCP clients (default $config_dhcp_default):"
echo "  dhcpcanon: $with_dhcpcanon"
echo "  dhclient: $with_dhclient"
echo "  dhcpcd: $with_dhcpcd"
echo

echo "Miscellaneous:"
echo "  have introspection: $have_introspection"
echo "  build documentation and manpages: $build_docs"
echo "  install pregenerated documentation and manpages: $use_pregen_docs"
echo "  tests: $enable_tests"
echo "  more-asserts: $more_asserts"
echo "  more-logging: $enable_more_logging"
echo "  more-warnings: $set_more_warnings"
echo "  valgrind: $with_valgrind   $with_valgrind_suppressions"
echo "  code coverage: $enable_code_coverage"
echo "  LTO: $enable_lto"
echo "  linker garbage collection: $enable_ld_gc"
echo "  JSON validation for libnm: $enable_json_validation"
echo "  crypto: $with_crypto (have-gnutls: $have_crypto_gnutls, have-nss: $have_crypto_nss)"
echo "  sanitizers: $sanitizers"
echo "  Mozilla Public Suffix List: $with_libpsl"
echo "  eBPF: $have_ebpf"
echo
