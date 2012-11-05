SUBDIRS = . tests

INCLUDES = \
	-I${top_srcdir}/src \
	-I${top_builddir}/src/generated \
	-I${top_srcdir}/src/generated \
	-I${top_srcdir}/src/logging \
	-I${top_builddir}/include \
	-I${top_srcdir}/include \
	-I${top_builddir}/libnm-util \
	-I${top_srcdir}/libnm-util

noinst_LTLIBRARIES = libsupplicant-manager.la

libsupplicant_manager_la_SOURCES = \
	nm-supplicant-types.h \
	nm-supplicant-manager.h \
	nm-supplicant-manager.c \
	nm-supplicant-config.h \
	nm-supplicant-config.c \
	nm-supplicant-interface.c \
	nm-supplicant-interface.h \
	nm-supplicant-settings-verify.h \
	nm-supplicant-settings-verify.c

libsupplicant_manager_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DNM_PKGDATADIR=\"$(pkgdatadir)\" \
	-DNM_LOCALSTATEDIR=\"$(localstatedir)\"

libsupplicant_manager_la_LIBADD = \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

