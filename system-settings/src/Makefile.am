INCLUDES = -I${top_srcdir} \
           -I${top_srcdir}/include \
           -I${top_srcdir}/libnm-util \
           -I${top_srcdir}/libnm-glib \
           -I${top_builddir}/marshallers

sbin_PROGRAMS = nm-system-settings

BUILT_SOURCES = \
	nm-settings-system-glue.h

nm_system_settings_SOURCES = \
	dbus-settings.c \
	dbus-settings.h \
	main.c \
	nm-polkit-helpers.c \
	nm-polkit-helpers.h \
	nm-system-config-error.c \
	nm-system-config-error.h \
	nm-system-config-interface.c \
	nm-system-config-interface.h \
	nm-system-config-hal-manager.c \
	nm-system-config-hal-manager.h \
	nm-sysconfig-connection.c \
	nm-sysconfig-connection.h \
	sha1.c \
	sha1.h

nm_system_settings_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GTHREAD_CFLAGS) \
	$(GMODULE_CFLAGS) \
	$(POLKIT_CFLAGS) \
	-DDBUS_API_SUBJECT_TO_CHANGE \
	-DG_DISABLE_DEPRECATED	\
	-DBINDIR=\"$(bindir)\" \
	-DSBINDIR=\"$(sbindir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DDATADIR=\"$(datadir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DPLUGINDIR=\"$(pkglibdir)\"

nm_system_settings_LDADD = \
	$(DBUS_LIBS) \
	$(GTHREAD_LIBS) \
	$(GMODULE_LIBS) \
	$(POLKIT_LIBS) \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm_glib.la \
	$(top_builddir)/marshallers/libmarshallers.la

nm_system_settings_LDFLAGS = -rdynamic

nm-settings-system-glue.h: $(top_srcdir)/introspection/nm-settings-system.xml
	dbus-binding-tool --prefix=nm_settings_system --mode=glib-server --output=$@ $<


dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = nm-system-settings.conf

dbusactivationdir = $(datadir)/dbus-1/system-services
dbusactivation_in_files = org.freedesktop.NetworkManagerSystemSettings.service.in
dbusactivation_DATA = $(dbusactivation_in_files:.service.in=.service)

%service: %service.in
	$(edit) $< >$@

edit = @sed \
	-e 's|@sbindir[@]|$(sbindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g' \
	-e 's|@libexecdir[@]|$(libexecdir)|g'

EXTRA_DIST = \
	$(dbusservice_DATA) \
	$(dbusactivation_in_files)

CLEANFILES = \
	$(BUILT_SOURCES) \
	$(dbusactivation_DATA)

