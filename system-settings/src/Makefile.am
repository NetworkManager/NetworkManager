INCLUDES = -I${top_srcdir} \
           -I${top_srcdir}/include \
           -I${top_srcdir}/libnm-util \
           -I${top_srcdir}/libnm-glib

sbin_PROGRAMS = nm-system-settings

nm_system_settings_SOURCES = \
	dbus-settings.c \
	dbus-settings.h \
	main.c \
	nm-system-config-interface.c \
	nm-system-config-interface.h

nm_system_settings_CPPFLAGS = \
	$(DBUS_CFLAGS)									\
	$(GTHREAD_CFLAGS)								\
	$(GMODULE_CFLAGS) \
	-DDBUS_API_SUBJECT_TO_CHANGE						\
	-DG_DISABLE_DEPRECATED							\
	-DBINDIR=\"$(bindir)\"							\
	-DSBINDIR=\"$(sbindir)\"							\
	-DLIBEXECDIR=\"$(libexecdir)\"					\
	-DDATADIR=\"$(datadir)\"							\
	-DSYSCONFDIR=\"$(sysconfdir)\"					\
	-DLOCALSTATEDIR=\"$(localstatedir)\"				\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"

nm_system_settings_LDADD = \
	$(DBUS_LIBS) \
	$(GTHREAD_LIBS) \
	$(GMODULE_LIBS) \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm_glib.la

nm_system_settings_LDFLAGS = -rdynamic

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = nm-system-settings.conf

EXTRA_DIST = \
	$(dbusservice_DATA)

