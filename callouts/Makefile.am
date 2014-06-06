SUBDIRS = . tests

AM_CPPFLAGS = \
	-I${top_srcdir}/include \
	-I${top_builddir}/include \
	-I${top_srcdir}/libnm-util \
	-I${top_builddir}/libnm-util \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DNMCONFDIR=\"$(nmconfdir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\"

###########################################
# Test libraries
###########################################

noinst_LTLIBRARIES = \
	libtest-dispatcher-envp.la


dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = \
	nm-dispatcher.conf \
	nm-avahi-autoipd.conf

libexec_PROGRAMS = \
	nm-dispatcher \
	nm-avahi-autoipd.action


nm_avahi_autoipd_action_SOURCES = \
	nm-avahi-autoipd-action.c

nm_avahi_autoipd_action_LDADD = \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)


nm_dispatcher_SOURCES = \
	nm-dispatcher.c \
	nm-dispatcher-api.h \
	nm-dispatcher-utils.c \
	nm-dispatcher-utils.h

nm_dispatcher_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

nm-dispatcher-glue.h: nm-dispatcher.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_dispatcher --mode=glib-server --output=$@ $<

###########################################
# dispatcher envp
###########################################

libtest_dispatcher_envp_la_SOURCES = \
	nm-dispatcher-utils.c \
	nm-dispatcher-utils.h

libtest_dispatcher_envp_la_CPPFLAGS = \
	$(AM_CPPFLAGS)

libtest_dispatcher_envp_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)


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
	   $(mkinstalldirs) -m 0755 $(DESTDIR)$(dispatcherdir)/pre-down.d
	   $(mkinstalldirs) -m 0755 $(DESTDIR)$(dispatcherdir)/pre-up.d

BUILT_SOURCES = nm-dispatcher-glue.h

CLEANFILES = $(BUILT_SOURCES) $(dbusactivation_DATA)

EXTRA_DIST = \
	$(dbusservice_DATA) \
	$(udevrules_DATA) \
	$(dbusactivation_in_files) \
	nm-dispatcher.xml

