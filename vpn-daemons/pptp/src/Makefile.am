INCLUDES = -I${top_srcdir}                  \
           -I${top_srcdir}/utils            \
           -I${top_srcdir}/vpn-daemons/pptp

AM_CPPFLAGS =							\
	$(DBUS_CFLAGS)						\
	$(GTHREAD_CFLAGS)					\
	$(NETWORK_MANAGER_CFLAGS)				\
	$(PPPD_CFLAGS)						\
	$(NM_VPN_CFLAGS)					\
	-Wall							\
	-DDBUS_API_SUBJECT_TO_CHANGE				\
	-DG_DISABLE_DEPRECATED					\
	-DBINDIR=\"$(bindir)\"					\
	-DPREFIX=\""$(prefix)"\"				\
	-DSYSCONFDIR=\""$(sysconfdir)"\"			\
	-DNM_VERSION="\"$(VERSION)\""				\
	-DLIBDIR=\""$(libdir)"\"				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DLOCALSTATEDIR=\""$(localstatedir)"\"		 	\
	-DDATADIR=\"$(datadir)\"				\
	-fPIC

bin_PROGRAMS = nm-ppp-starter

pppdplugindir = $(PPPD_PLUGIN_DIR)
pppdplugin_PROGRAMS = nm-pppd-plugin.so

nm_ppp_starter_SOURCES =			\
				nm-ppp-starter.c	\
				nm-ppp-starter.h	\
				nm-utils.c			\
				nm-utils.h			\
				external/2.4.3/pppd/patchlevel.h \
				external/2.4.3/pppd/ipcp.h \
				external/2.4.3/pppd/pppd.h \
				external/2.4.3/pppd/fsm.h \
				external/2.4.4/pppd/patchlevel.h \
				external/2.4.4/pppd/ipcp.h \
				external/2.4.4/pppd/pppd.h \
				external/2.4.4/pppd/fsm.h \
				external/2.4.4b1/pppd/patchlevel.h \
				external/2.4.4b1/pppd/ipcp.h \
				external/2.4.4b1/pppd/pppd.h \
				external/2.4.4b1/pppd/fsm.h

nm_ppp_starter_LDADD = 				\
				$(DBUS_LIBS)		\
				$(GTHREAD_LIBS)		\
				$(NETWORK_MANAGER_LIBS)

nm_pppd_plugin_so_SOURCES = 		\
				nm-pppd-plugin.c 	\
				nm-pppd-plugin.h  	\
				nm-ppp-starter.h

nm_pppd_plugin_so_LDFLAGS = 		\
				-shared 

nm_pppd_plugin_so_LDADD = 		\
				$(DBUS_LIBS)	\
				$(GTHREAD_LIBS)

CLEANFILES = *~
