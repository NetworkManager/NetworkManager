SUBDIRS = . tests

libexec_PROGRAMS = \
	nm-dispatcher

noinst_LTLIBRARIES = \
	libnm-dispatcher-core.la \
	libnmdbus-dispatcher.la

AM_CPPFLAGS = \
	-I${top_srcdir}/shared \
	-I${top_builddir}/shared \
	-I${top_srcdir}/libnm-core \
	-I${top_builddir}/libnm-core \
	$(GLIB_CFLAGS) \
	-DNETWORKMANAGER_COMPILATION \
	-DNMCONFDIR=\"$(nmconfdir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\"

###############################################################################

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = \
	nm-dispatcher.conf

###############################################################################

libnm_dispatcher_core_la_SOURCES = \
	$(top_srcdir)/shared/nm-dispatcher-api.h \
	nm-dispatcher-utils.c \
	nm-dispatcher-utils.h

libnm_dispatcher_core_la_LIBADD = \
	$(top_builddir)/libnm/libnm.la \
	$(GLIB_LIBS)

###############################################################################

nm_dispatcher_SOURCES = \
	$(top_srcdir)/shared/nm-dispatcher-api.h \
	nm-dispatcher.c

nm_dispatcher_LDFLAGS = \
	-Wl,--version-script="$(top_srcdir)/linker-script-binary.ver"

nm_dispatcher_LDADD = \
	$(top_builddir)/libnm/libnm.la \
	libnm-dispatcher-core.la \
	libnmdbus-dispatcher.la \
	$(GLIB_LIBS)

###############################################################################

nodist_libnmdbus_dispatcher_la_SOURCES = \
	nmdbus-dispatcher.c \
	nmdbus-dispatcher.h

libnmdbus_dispatcher_la_CPPFLAGS = $(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(AM_CPPFLAGS))

nmdbus-dispatcher.h: nm-dispatcher.xml
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--c-namespace NMDBus \
		--interface-prefix org.freedesktop \
		$<

nmdbus-dispatcher.c: nmdbus-dispatcher.h
	@true

BUILT_SOURCES = nmdbus-dispatcher.h nmdbus-dispatcher.c

###############################################################################

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
	   $(mkinstalldirs) -m 0755 $(DESTDIR)$(dispatcherdir)/no-wait.d

###############################################################################

CLEANFILES = \
	$(BUILT_SOURCES) \
	$(dbusactivation_DATA)

EXTRA_DIST = \
	$(dbusservice_DATA) \
	$(dbusactivation_in_files) \
	nm-dispatcher.xml

