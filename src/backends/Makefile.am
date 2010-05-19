INCLUDES = \
	-I${top_srcdir} \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/include \
	-I${top_srcdir}/src \
	-I${top_srcdir}/src/vpn-manager \
	-I${top_srcdir}/src/named-manager \
	-I${top_srcdir}/libnm-util

noinst_LTLIBRARIES = libnmbackend.la

libnmbackend_la_SOURCES = NetworkManagerGeneric.c	\
				NetworkManagerGeneric.h

libnmbackend_la_LIBADD =

if TARGET_REDHAT
libnmbackend_la_SOURCES += NetworkManagerRedHat.c
endif

if TARGET_SUSE
libnmbackend_la_SOURCES += NetworkManagerSuSE.c
endif

if TARGET_GENTOO
libnmbackend_la_SOURCES += NetworkManagerGentoo.c
endif

if TARGET_DEBIAN
libnmbackend_la_SOURCES += NetworkManagerDebian.c
endif

if TARGET_SLACKWARE
libnmbackend_la_SOURCES += NetworkManagerSlackware.c
endif

if TARGET_ARCH
libnmbackend_la_SOURCES += NetworkManagerArch.c
endif

if TARGET_PALDO
libnmbackend_la_SOURCES += NetworkManagerPaldo.c
endif

if TARGET_FRUGALWARE
libnmbackend_la_SOURCES += NetworkManagerFrugalware.c
libnmbackend_la_LIBADD += -lfwnetconfig -lfwutil
endif

if TARGET_MANDRIVA
libnmbackend_la_SOURCES += NetworkManagerMandriva.c
endif

if TARGET_PARDUS
libnmbackend_la_SOURCES += NetworkManagerPardus.c
endif

libnmbackend_la_LIBADD += \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

libnmbackend_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DBINDIR=\"$(bindir)\" \
	-DDATADIR=\"$(datadir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\"

