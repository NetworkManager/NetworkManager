SUBDIRS=plugins . tests

INCLUDES = -I${top_srcdir} \
           -I${top_srcdir}/include \
           -I${top_srcdir}/libnm-util \
           -I${top_srcdir}/src/logging \
           -I${top_srcdir}/src \
           -I${top_builddir}/marshallers

noinst_LTLIBRARIES = libsettings.la libtest-settings-utils.la

libtest_settings_utils_la_SOURCES = \
	nm-settings-utils.c \
	nm-settings-utils.h

libtest_settings_utils_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS)

libtest_settings_utils_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

BUILT_SOURCES = \
	nm-settings-glue.h \
	nm-settings-connection-glue.h \
	nm-agent-manager-glue.h

libsettings_la_SOURCES = \
	nm-settings.c \
	nm-settings.h \
	nm-inotify-helper.c \
	nm-inotify-helper.h \
	nm-settings-error.c \
	nm-settings-error.h \
	nm-system-config-interface.c \
	nm-system-config-interface.h \
	nm-settings-connection.c \
	nm-settings-connection.h \
	nm-default-wired-connection.c \
	nm-default-wired-connection.h \
	nm-agent-manager.c \
	nm-agent-manager.h \
	nm-secret-agent.c \
	nm-secret-agent.h \
	nm-settings-utils.h \
	nm-settings-utils.c

libsettings_la_CPPFLAGS = \
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

libsettings_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/marshallers/libmarshallers.la \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(builddir)/plugins/keyfile/libnm-settings-plugin-keyfile.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(POLKIT_LIBS)

libsettings_la_LDFLAGS = -rdynamic

nm-settings-glue.h: $(top_srcdir)/introspection/nm-settings.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_settings --mode=glib-server --output=$@ $<

nm-settings-connection-glue.h: $(top_srcdir)/introspection/nm-settings-connection.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_settings_connection --mode=glib-server --output=$@ $<

nm-agent-manager-glue.h: $(top_srcdir)/introspection/nm-agent-manager.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_agent_manager --mode=glib-server --output=$@ $<

CLEANFILES = \
	$(BUILT_SOURCES)

