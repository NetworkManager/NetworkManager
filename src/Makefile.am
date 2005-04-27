SUBDIRS=named-manager vpn-manager backends

INCLUDES = -I${top_srcdir} -I${top_srcdir}/src/named-manager -I${top_srcdir}/src/vpn-manager -I${top_srcdir}/utils

bin_PROGRAMS = NetworkManager

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
		nm-ip4-config.c			\
		nm-ip4-config.h			\
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
		nm-netlink-monitor.c		\
		nm-netlink-monitor.h		\
		autoip.c

NetworkManager_CPPFLAGS = 			\
	$(DBUS_CFLAGS)					\
	$(GTHREAD_CFLAGS)				\
	$(HAL_CFLAGS)					\
	$(OPENSSL_CFLAGS)				\
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

NetworkManager_LDADD = 							\
			$(DBUS_LIBS)						\
			$(GTHREAD_LIBS)					\
			$(HAL_LIBS)						\
			$(IWLIB)							\
			$(top_builddir)/utils/libnmutils.la	\
			../dhcpcd/libdhcpc.a				\
			./named-manager/libnamed-manager.la	\
			./vpn-manager/libvpn-manager.la		\
			./backends/libnmbackend.la

if WITH_GCRYPT
NetworkManager_LDADD += $(LIBGCRYPT_LIBS)
endif

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = NetworkManager.conf

helperdir = $(bindir)
helper_SCRIPTS = NMLoadModules

EXTRA_DIST = $(dbusservice_DATA) $(helper_SCRIPTS)
