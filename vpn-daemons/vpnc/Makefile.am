INCLUDES = -I${top_srcdir}  -I${top_srcdir}/utils

AM_CPPFLAGS =								\
	$(DBUS_CFLAGS)							\
	$(GTHREAD_CFLAGS)						\
	-Wall								\
	-DDBUS_API_SUBJECT_TO_CHANGE				\
	-DG_DISABLE_DEPRECATED					\
	-DBINDIR=\"$(bindir)\"					\
	-DPREFIX=\""$(prefix)"\"					\
	-DSYSCONFDIR=\""$(sysconfdir)"\"			\
	-DVERSION="\"$(VERSION)\""				\
	-DLIBDIR=\""$(libdir)"\"					\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DLOCALSTATEDIR=\""$(localstatedir)"\"		\
	-DDATADIR=\"$(datadir)\"

bin_PROGRAMS = nm-vpnc-service nm-vpnc-service-vpnc-helper

nm_vpnc_service_SOURCES = \
				nm-vpnc-service.c

nm_vpnc_service_LDADD = \
				$(DBUS_LIBS)			\
				$(GTHREAD_LIBS)		\
				$(top_builddir)/utils/libnmutils.la


nm_vpnc_service_vpnc_helper_SOURCES = \
				nm-vpnc-service-vpnc-helper.c

nm_vpnc_service_vpnc_helper_LDADD = \
				$(DBUS_LIBS)			\
				$(GTHREAD_LIBS)		\
				$(top_builddir)/utils/libnmutils.la


dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = nm-vpnc-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = nm-vpnc-service.name

EXTRA_DIST = $(dbusservice_DATA) $(nmvpnservice_DATA)

