SUBDIRS=. tests

pkglib_LTLIBRARIES = libnm-settings-plugin-ifcfg-rh.la

noinst_LTLIBRARIES = libifcfg-rh-io.la

libifcfg_rh_io_la_SOURCES = \
	shvar.c \
	shvar.h \
	reader.c \
	reader.h \
	writer.c \
	writer.h \
	sha1.c \
	sha1.h \
	errors.c \
	common.h

libifcfg_rh_io_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-DSYSCONFDIR=\"$(sysconfdir)\"

libifcfg_rh_io_la_LIBADD = $(GLIB_LIBS)

libnm_settings_plugin_ifcfg_rh_la_SOURCES = \
	plugin.c \
	plugin.h \
	nm-ifcfg-connection.c \
	nm-ifcfg-connection.h

libnm_settings_plugin_ifcfg_rh_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GMODULE_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-I$(top_srcdir)/system-settings/src \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/marshallers \
	-DSYSCONFDIR=\"$(sysconfdir)\"

libnm_settings_plugin_ifcfg_rh_la_LDFLAGS = -module -avoid-version
libnm_settings_plugin_ifcfg_rh_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm_glib.la \
	$(top_builddir)/marshallers/libmarshallers.la \
	libifcfg-rh-io.la

if NO_GIO
libnm_settings_plugin_ifcfg_rh_la_LIBADD += \
	$(top_builddir)/gfilemonitor/libgfilemonitor.la
else
libnm_settings_plugin_ifcfg_rh_la_LIBADD += \
	$(GIO_LIBS)
endif

