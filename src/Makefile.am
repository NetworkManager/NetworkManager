
INCLUDES = -I${top_srcdir}

AM_CPPFLAGS = 						\
	$(NM_CFLAGS) 			   		\
	$(OPENSSL_CFLAGS)				\
	-Wall						\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DG_DISABLE_DEPRECATED			\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

bin_PROGRAMS = NetworkManager

noinst_LTLIBRARIES = libnmbackend.la

NetworkManager_SOURCES =				\
		NetworkManagerAP.c			\
		NetworkManagerAP.h			\
		NetworkManagerAPList.c		\
		NetworkManagerAPList.h		\
		NetworkManagerDbus.c		\
		NetworkManagerDbus.h		\
		NetworkManagerDHCP.c		\
		NetworkManagerDHCP.h		\
		NetworkManagerDevice.c		\
		NetworkManagerDevice.h		\
		NetworkManager.c			\
		NetworkManagerMain.h		\
		NetworkManagerPolicy.c		\
		NetworkManagerPolicy.h		\
		NetworkManagerUtils.c		\
		NetworkManagerUtils.h		\
		NetworkManagerWireless.c		\
		NetworkManagerWireless.h		\
		NetworkManagerSystem.c		\
		NetworkManagerSystem.h

if !WITH_GCRYPT
NetworkManager_SOURCES += gnome-keyring-md5.c gnome-keyring-md5.h
endif

NetworkManager_LDADD = $(NM_LIBS) $(IWLIB) libnmbackend.la ../dhcpcd/libdhcpc.a
if WITH_GCRYPT
NetworkManager_LDADD += $(LIBGCRYPT_LIBS)
endif

libnmbackend_la_SOURCES =

if TARGET_REDHAT
libnmbackend_la_SOURCES += backends/NetworkManagerRedHat.c \
		backends/shvar.c	\
		backends/shvar.h
endif
if TARGET_GENTOO
libnmbackend_la_SOURCES += backends/NetworkManagerGentoo.c
endif
if TARGET_DEBIAN
libnmbackend_la_SOURCES += backends/NetworkManagerDebian.c \
		backends/interface_parser.c	\
		backends/interface_parser.h	
endif
if TARGET_SLACKWARE
libnmbackend_la_SOURCES += backends/NetworkManagerSlackware.c
endif

libnmbackend_la_LIBADD = $(NM_LIBS)
libnmbackend_la_CPPFLAGS = $(NM_CFLAGS)

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = NetworkManager.conf

helperdir = $(bindir)
helper_SCRIPTS = NMLoadModules

EXTRA_DIST = $(dbusservice_DATA) $(helper_SCRIPTS)
