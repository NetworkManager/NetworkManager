INCLUDES = -I${top_srcdir}  -I${top_srcdir}/utils -I${top_srcdir}/vpn-daemons/openvpn

AM_CPPFLAGS =							\
	$(DBUS_CFLAGS)						\
	$(GTHREAD_CFLAGS)					\
	$(NETWORK_MANAGER_CFLAGS)				\
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

bin_PROGRAMS = nm-openvpn-service nm-openvpn-service-openvpn-helper

nm_openvpn_service_SOURCES =				\
				nm-openvpn-service.c	\
				nm-openvpn-service.h	\
				nm-utils.c		\
				nm-utils.h


nm_openvpn_service_LDADD = 						\
				$(DBUS_LIBS)				\
				$(GTHREAD_LIBS)				\
				$(NETWORK_MANAGER_LIBS)


nm_openvpn_service_openvpn_helper_SOURCES = 					\
				nm-openvpn-service-openvpn-helper.c

nm_openvpn_service_openvpn_helper_LDADD = 					\
				$(DBUS_LIBS)				\
				$(GTHREAD_LIBS)				\
				$(NETWORK_MANAGER_LIBS)

CLEANFILES = *~
