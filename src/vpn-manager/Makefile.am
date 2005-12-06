INCLUDES = -I${top_srcdir}                       \
           -I${top_srcdir}/include               \
           -I${top_srcdir}/utils                 \
           -I${top_srcdir}/src                   \
           -I${top_srcdir}/src/named-manager

noinst_LTLIBRARIES = libvpn-manager.la

libvpn_manager_la_SOURCES =	nm-dbus-vpn.c			\
						nm-dbus-vpn.h			\
						nm-vpn-connection.c		\
						nm-vpn-connection.h		\
						nm-vpn-manager.c		\
						nm-vpn-manager.h		\
						nm-vpn-service.c		\
						nm-vpn-service.h		\
						nm-vpn-act-request.c	\
						nm-vpn-act-request.h

libvpn_manager_la_CPPFLAGS =	$(DBUS_CFLAGS)					\
						$(GTHREAD_CFLAGS)				\
						$(HAL_CFLAGS)					\
						-g							\
						-Wall						\
						-DDBUS_API_SUBJECT_TO_CHANGE		\
						-DG_DISABLE_DEPRECATED			\
						-DBINDIR=\"$(bindir)\"			\
						-DDATADIR=\"$(datadir)\"			\
						-DSYSCONFDIR=\"$(sysconfdir)\"


libvpn_manager_la_LIBADD = $(DBUS_LIBS) $(GTHREAD_LIBS)
