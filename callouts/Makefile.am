SUBDIRS = . tests

AM_CPPFLAGS = \
	-I${top_srcdir}/include \
	-I${top_srcdir}/libnm-core \
	-I${top_builddir}/libnm-core \
	$(GLIB_CFLAGS) \
	-DNETWORKMANAGER_COMPILATION \
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
	nm-dispatcher.conf

libexec_PROGRAMS = \
	nm-dispatcher


nm_dispatcher_SOURCES = \
	nm-dispatcher.c \
	nm-dispatcher-api.h \
	nm-dispatcher-utils.c \
	nm-dispatcher-utils.h

nm_dispatcher_LDADD = \
	$(top_builddir)/libnm/libnm.la \
	libnmdbus-dispatcher.la \
	$(GLIB_LIBS)

# See note about gdbus-codegen in introspection/Makefile.am

noinst_LTLIBRARIES += libnmdbus-dispatcher.la

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

###########################################
# dispatcher envp
###########################################

libtest_dispatcher_envp_la_SOURCES = \
	nm-dispatcher-utils.c \
	nm-dispatcher-utils.h

libtest_dispatcher_envp_la_CPPFLAGS = \
	$(AM_CPPFLAGS)

libtest_dispatcher_envp_la_LIBADD = \
	$(top_builddir)/libnm/libnm.la \
	$(GLIB_LIBS)


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

CLEANFILES = $(nodist_libnmdbus_dispatcher_la_SOURCES) $(dbusactivation_DATA)

EXTRA_DIST = \
	$(dbusservice_DATA) \
	$(dbusactivation_in_files) \
	nm-dispatcher.xml

