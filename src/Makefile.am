INCLUDES = -I${top_srcdir} -I${top_srcdir}/named

bin_PROGRAMS = NetworkManager

noinst_LTLIBRARIES = libnmbackend.la

NetworkManager_SOURCES =				\
		NetworkManagerAP.c			\
		NetworkManagerAP.h			\
		NetworkManagerAPList.c		\
		NetworkManagerAPList.h		\
		NetworkManagerDbus.c		\
		NetworkManagerDbus.h		\
		NetworkManagerDbusUtils.c	\
		NetworkManagerDbusUtils.h	\
		nm-dbus-nm.c				\
		nm-dbus-nm.h				\
		nm-dbus-device.c			\
		nm-dbus-device.h			\
		nm-dbus-net.c				\
		nm-dbus-net.h				\
		nm-dbus-dhcp.c				\
		nm-dbus-dhcp.h				\
		nm-dbus-nmi.c				\
		nm-dbus-nmi.h				\
		NetworkManagerDHCP.c		\
		NetworkManagerDHCP.h		\
		NetworkManagerDevice.c		\
		NetworkManagerDevice.h		\
		NetworkManagerDevicePrivate.h	\
		NetworkManager.c			\
		NetworkManagerMain.h		\
		NetworkManagerPolicy.c		\
		NetworkManagerPolicy.h		\
		NetworkManagerUtils.c		\
		NetworkManagerUtils.h		\
		NetworkManagerWireless.c		\
		NetworkManagerWireless.h		\
		NetworkManagerSystem.c		\
		NetworkManagerSystem.h		\
		autoip.c

NetworkManager_CPPFLAGS = 			\
	$(DBUS_CFLAGS)					\
	$(GTHREAD_CFLAGS)				\
	$(HAL_CFLAGS)					\
	$(OPENSSL_CFLAGS)				\
	-g							\
	-Wall						\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DG_DISABLE_DEPRECATED			\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"			\
	-DSYSCONFDIR=\"$(sysconfdir)\"	\
	-DARP_DEBUG
if WITH_GCRYPT
NetworkManager_CPPFLAGS += $(LIBGCRYPT_CFLAGS)
endif


if !WITH_GCRYPT
NetworkManager_SOURCES += gnome-keyring-md5.c gnome-keyring-md5.h
endif

NetworkManager_LDADD = $(DBUS_LIBS) $(GTHREAD_LIBS) $(HAL_LIBS) $(IWLIB) libnmbackend.la ../dhcpcd/libdhcpc.a ../named/libnamed.la
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

libnmbackend_la_LIBADD = $(DBUS_LIBS) $(GTHREAD_LIBS)
libnmbackend_la_CFLAGS = $(NetworkManager_CPPFLAGS)

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = NetworkManager.conf

helperdir = $(bindir)
helper_SCRIPTS = NMLoadModules

EXTRA_DIST = $(dbusservice_DATA) $(helper_SCRIPTS)
