INCLUDES = \
	-I${top_srcdir} \
	-I${top_srcdir}/include \
	-I${top_srcdir}/libnm-util \
	-I${top_srcdir}/src \
	-I${top_srcdir}/src/logging \
	-I${top_builddir}/marshallers \
	-I$(top_srcdir)/src/nm-bluez-manager

noinst_LTLIBRARIES = libbluez-manager.la

libbluez_manager_la_SOURCES = \
	nm-bluez-manager.c \
	nm-bluez-manager.h \
	nm-bluez-adapter.c \
	nm-bluez-adapter.h \
	nm-bluez-device.c \
	nm-bluez-device.h \
	nm-bluez-common.h

libbluez_manager_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(BLUEZ_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DBINDIR=\"$(bindir)\" \
	-DDATADIR=\"$(datadir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\"

libbluez_manager_la_LIBADD = \
	$(top_builddir)/marshallers/libmarshallers.la \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(BLUEZ_LIBS)

