SUBDIRS=named-manager vpn-manager dhcp-manager backends

INCLUDES = -I${top_srcdir}                   \
           -I${top_srcdir}/include           \
           -I${top_srcdir}/src/named-manager \
           -I${top_srcdir}/src/vpn-manager   \
           -I${top_srcdir}/src/dhcp-manager  \
           -I${top_srcdir}/utils			\
           -I${top_srcdir}/libnm-util

sbin_PROGRAMS = NetworkManager

NetworkManager_SOURCES =				\
		nm-device.c				\
		nm-device.h				\
		nm-device-private.h			\
		nm-device-802-3-ethernet.c	\
		nm-device-802-3-ethernet.h	\
		nm-device-802-11-wireless.c	\
		nm-device-802-11-wireless.h	\
		NetworkManagerAP.c			\
		NetworkManagerAP.h			\
		NetworkManagerAPList.c		\
		NetworkManagerAPList.h		\
		NetworkManagerDbus.c		\
		NetworkManagerDbus.h		\
		NetworkManagerDbusUtils.c	\
		NetworkManagerDialup.h		\
		NetworkManagerDbusUtils.h	\
		nm-dbus-nm.c				\
		nm-dbus-nm.h				\
		nm-dbus-device.c			\
		nm-dbus-device.h			\
		nm-dbus-net.c				\
		nm-dbus-net.h				\
		nm-dbus-nmi.c				\
		nm-dbus-nmi.h				\
		nm-ip4-config.c			\
		nm-ip4-config.h			\
		NetworkManager.c			\
		NetworkManagerMain.h		\
		NetworkManagerPolicy.c		\
		NetworkManagerPolicy.h		\
		NetworkManagerUtils.c		\
		NetworkManagerUtils.h		\
		NetworkManagerSystem.c		\
		NetworkManagerSystem.h		\
		nm-netlink-monitor.c		\
		nm-netlink-monitor.h		\
		nm-activation-request.c		\
		nm-activation-request.h		\
		autoip.c					\
		autoip.h					\
		nm-ap-security.c			\
		nm-ap-security.h			\
		nm-ap-security-private.h		\
		nm-ap-security-wep.c		\
		nm-ap-security-wep.h		\
		nm-ap-security-wpa-psk.c		\
		nm-ap-security-wpa-psk.h		\
		wpa.c					\
		wpa.h					\
		wpa_ctrl.c				\
		wpa_ctrl.h

NetworkManager_CPPFLAGS = 			\
	$(DBUS_CFLAGS)					\
	$(GTHREAD_CFLAGS)				\
	$(HAL_CFLAGS)					\
	$(OPENSSL_CFLAGS)				\
	$(LIBNL_CFLAGS)				\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DG_DISABLE_DEPRECATED			\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"			\
	-DSYSCONFDIR=\"$(sysconfdir)\"	\
	-DARP_DEBUG


NetworkManager_LDADD = 							\
			$(DBUS_LIBS)						\
			$(GTHREAD_LIBS)					\
			$(HAL_LIBS)						\
			$(IWLIB)							\
			$(LIBNL_LIBS)						\
			$(top_builddir)/utils/libnmutils.la	\
			./named-manager/libnamed-manager.la	\
			./vpn-manager/libvpn-manager.la		\
			./dhcp-manager/libdhcp-manager.la		\
			./backends/libnmbackend.la			\
			$(top_builddir)/libnm-util/libnm-util.la

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = NetworkManager.conf

EXTRA_DIST = $(dbusservice_DATA)
