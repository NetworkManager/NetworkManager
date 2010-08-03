dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = \
	nm-dhcp-client.conf \
	nm-dispatcher.conf \
	nm-avahi-autoipd.conf

libexec_PROGRAMS = \
	nm-dhcp-client.action \
	nm-dispatcher.action \
	nm-avahi-autoipd.action

nm_dhcp_client_action_SOURCES = \
	nm-dhcp-client-action.c

nm_dhcp_client_action_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\"

nm_dhcp_client_action_LDADD = \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)


nm_avahi_autoipd_action_SOURCES = \
	nm-avahi-autoipd-action.c

nm_avahi_autoipd_action_CPPFLAGS = 		\
	$(DBUS_CFLAGS)						\
	$(GLIB_CFLAGS)					\
	-DG_DISABLE_DEPRECATED				\
	-DSYSCONFDIR=\"$(sysconfdir)\"		\
	-DLIBEXECDIR=\"$(libexecdir)\"

nm_avahi_autoipd_action_LDADD = \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)


nm_dispatcher_action_SOURCES = \
	nm-dispatcher-action.c \
	nm-dispatcher-action.h

nm_dispatcher_action_CPPFLAGS = \
	-I${top_srcdir} \
	-I${top_srcdir}/include \
	-I${top_srcdir}/libnm-util \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\"

nm_dispatcher_action_LDADD = \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

nm-dispatcher-glue.h: nm-dispatcher.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_dispatcher --mode=glib-server --output=$@ $<

udevrulesdir = $(UDEV_BASE_DIR)/rules.d
udevrules_DATA = 77-nm-olpc-mesh.rules

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

dispatcherdir=$(sysconfdir)/NetworkManager/dispatcher.d
install-data-hook:
	   $(mkinstalldirs) -m 0755 $(DESTDIR)$(dispatcherdir)

BUILT_SOURCES = nm-dispatcher-glue.h

CLEANFILES = $(BUILT_SOURCES) $(dbusactivation_DATA)

EXTRA_DIST = \
	$(dbusservice_DATA) \
	$(udevrules_DATA) \
	$(dbusactivation_in_files) \
	nm-dispatcher.xml

