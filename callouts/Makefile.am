dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = \
	nm-dhcp-client.conf \
	nm-dispatcher.conf

libexec_PROGRAMS = \
	nm-dhcp-client.action \
	nm-dispatcher.action

nm_dhcp_client_action_SOURCES = \
	nm-dhcp-client-action.c

nm_dhcp_client_action_CPPFLAGS = 		\
	$(DBUS_CFLAGS)						\
	$(GTHREAD_CFLAGS)					\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DG_DISABLE_DEPRECATED				\
	-DSYSCONFDIR=\"$(sysconfdir)\"		\
	-DLIBEXECDIR=\"$(libexecdir)\"

nm_dhcp_client_action_LDADD = \
	$(DBUS_LIBS) \
	$(GTHREAD_LIBS)


nm_dispatcher_action_SOURCES = \
	nm-dispatcher-action.c \
	nm-dispatcher-action.h

nm_dispatcher_action_CPPFLAGS = \
	-I${top_srcdir} \
	-I${top_srcdir}/include \
	-I${top_srcdir}/libnm-util \
	$(DBUS_CFLAGS) \
	$(GTHREAD_CFLAGS) \
	-DDBUS_API_SUBJECT_TO_CHANGE \
	-DG_DISABLE_DEPRECATED \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\"

nm_dispatcher_action_LDADD = \
	$(DBUS_LIBS) \
	$(GTHREAD_LIBS) \
	$(top_builddir)/libnm-util/libnm-util.la

nm-dispatcher-glue.h: nm-dispatcher.xml
	dbus-binding-tool --prefix=nm_dispatcher --mode=glib-server --output=nm-dispatcher-glue.h $(top_srcdir)/callouts/nm-dispatcher.xml

dbusactivationdir = $(datadir)/dbus-1/system-services
dbusactivation_in_files = org.freedesktop.nm_dispatcher.service.in
dbusactivation_DATA = $(dbusactivation_in_files:.service.in=.service)

%.service: %.service.in
	$(edit) $< >$@

edit = @sed \
	-e 's|@sbindir[@]|$(sbindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g' \
	-e 's|@libexecdir[@]|$(libexecdir)|g'

BUILT_SOURCES = nm-dispatcher-glue.h

CLEANFILES = $(BUILT_SOURCES) $(dbusactivation_DATA)

EXTRA_DIST = \
	$(dbusservice_DATA) \
	$(dbusactivation_in_files) \
	nm-dispatcher.xml

