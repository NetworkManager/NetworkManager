INCLUDES = -I${top_srcdir} -I./named-manager -I./vpn-manager -I${top_srcdir}/utils

noinst_LTLIBRARIES = libnmbackend.la

libnmbackend_la_SOURCES =

if TARGET_REDHAT
libnmbackend_la_SOURCES +=	NetworkManagerRedHat.c	\
						shvar.c				\
						shvar.h
endif

if TARGET_GENTOO
libnmbackend_la_SOURCES +=	NetworkManagerGentoo.c
endif

if TARGET_DEBIAN
libnmbackend_la_SOURCES +=	NetworkManagerDebian.c	\
						interface_parser.c		\
						interface_parser.h	
endif

if TARGET_SLACKWARE
libnmbackend_la_SOURCES +=	NetworkManagerSlackware.c
endif

libnmbackend_la_LIBADD = $(DBUS_LIBS) $(GTHREAD_LIBS)
libnmbackend_la_CFLAGS = $(NetworkManager_CPPFLAGS)


