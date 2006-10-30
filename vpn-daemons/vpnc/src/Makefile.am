INCLUDES = -I${top_srcdir} -I${top_srcdir}/utils -I${top_srcdir}/vpn-daemons/vpnc

AM_CPPFLAGS =							\
	$(DBUS_CFLAGS)						\
	$(GTHREAD_CFLAGS)					\
	$(NETWORK_MANAGER_CFLAGS)                               \
	-Wall							\
	-DDBUS_API_SUBJECT_TO_CHANGE				\
	-DG_DISABLE_DEPRECATED					\
	-DBINDIR=\"$(bindir)\"					\
	-DPREFIX=\""$(prefix)"\"				\
	-DSYSCONFDIR=\""$(sysconfdir)"\"			\
	-DVERSION="\"$(VERSION)\""				\
	-DLIBDIR=\""$(libdir)"\"				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DLOCALSTATEDIR=\""$(localstatedir)"\"		 	\
	-DDATADIR=\"$(datadir)\"

bin_PROGRAMS = nm-vpnc-service nm-vpnc-service-vpnc-helper

nm_vpnc_service_SOURCES =				\
				nm-vpnc-service.c	\
				nm-vpnc-service.h	\
				nm-utils.c		\
				nm-utils.h


nm_vpnc_service_LDADD = 						\
				$(DBUS_LIBS)				\
				$(GTHREAD_LIBS)				\
				$(NETWORK_MANAGER_LIBS)


nm_vpnc_service_vpnc_helper_SOURCES = 					\
				nm-vpnc-service-vpnc-helper.c

nm_vpnc_service_vpnc_helper_LDADD = 					\
				$(DBUS_LIBS)				\
				$(GTHREAD_LIBS)				\
				$(NETWORK_MANAGER_LIBS)

CLEANFILES = *~
