INCLUDES = -I${top_srcdir} \
           -I${top_srcdir}/include \
           -I${top_srcdir}/libnm-util \
           -I${top_srcdir}/libnm-glib \
           -I${top_srcdir}/src/logging \
           -I${top_srcdir}/src \
           -I${top_builddir}/marshallers

noinst_LTLIBRARIES = libsystem-settings.la

BUILT_SOURCES = \
	nm-settings-system-glue.h

libsystem_settings_la_SOURCES = \
	nm-sysconfig-settings.c \
	nm-sysconfig-settings.h \
	nm-inotify-helper.c \
	nm-inotify-helper.h \
	nm-polkit-helpers.h \
	nm-system-config-error.c \
	nm-system-config-error.h \
	nm-system-config-interface.c \
	nm-system-config-interface.h \
	nm-sysconfig-connection.c \
	nm-sysconfig-connection.h \
	nm-default-wired-connection.c \
	nm-default-wired-connection.h

libsystem_settings_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GMODULE_CFLAGS) \
	$(POLKIT_CFLAGS) \
	-DG_DISABLE_DEPRECATED	\
	-DBINDIR=\"$(bindir)\" \
	-DSBINDIR=\"$(sbindir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DDATADIR=\"$(datadir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DPLUGINDIR=\"$(pkglibdir)\"

libsystem_settings_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(top_builddir)/marshallers/libmarshallers.la \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(POLKIT_LIBS)

libsystem_settings_la_LDFLAGS = -rdynamic

nm-settings-system-glue.h: $(top_srcdir)/introspection/nm-settings-system.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_settings_system --mode=glib-server --output=$@ $<

CLEANFILES = \
	$(BUILT_SOURCES)

