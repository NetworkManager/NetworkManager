INCLUDES = -I${top_srcdir}				\
		 -I${top_srcdir}/include			\
		 -I${top_srcdir}/utils			\
		 -I${top_srcdir}/src			\
		 -I${top_srcdir}/src/vpn-manager	\
		 -I${top_srcdir}/src/named-manager	\
		 -I${top_srcdir}/libnm-util

noinst_LTLIBRARIES = libnmbackend.la

libnmbackend_la_SOURCES =

if TARGET_REDHAT
libnmbackend_la_SOURCES +=	NetworkManagerRedHat.c	\
						shvar.c				\
						shvar.h
endif

if TARGET_SUSE
libnmbackend_la_SOURCES +=	NetworkManagerSuSE.c				\
						shvar.c				\
						shvar.h
endif

if TARGET_GENTOO
libnmbackend_la_SOURCES +=	NetworkManagerGentoo.c		\
						shvar.c				\
						shvar.h
endif

if TARGET_DEBIAN
libnmbackend_la_SOURCES +=	NetworkManagerDebian.c	\
						interface_parser.c		\
						interface_parser.h	
endif

if TARGET_SLACKWARE
libnmbackend_la_SOURCES +=	NetworkManagerSlackware.c
endif

if TARGET_ARCH
libnmbackend_la_SOURCES +=	NetworkManagerArch.c
endif

libnmbackend_la_LIBADD = $(DBUS_LIBS) $(GTHREAD_LIBS)
libnmbackend_la_CPPFLAGS =	$(DBUS_CFLAGS)				\
					$(GTHREAD_CFLAGS)				\
					$(HAL_CFLAGS)					\
					-g							\
					-Wall						\
					-DDBUS_API_SUBJECT_TO_CHANGE		\
					-DG_DISABLE_DEPRECATED			\
					-DBINDIR=\"$(bindir)\"			\
					-DDATADIR=\"$(datadir)\"			\
					-DSYSCONFDIR=\"$(sysconfdir)\"

