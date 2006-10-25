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
		nm-logging.c				\
		nm-logging.h				\
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
		nm-ap-security-wpa-eap.c		\
		nm-ap-security-wpa-eap.h		\
		nm-ap-security-wpa-psk.c		\
		nm-ap-security-wpa-psk.h		\
		nm-ap-security-leap.c   		\
		nm-ap-security-leap.h   		\
		nm-marshal-main.c			\
		kernel-types.h				\
		wpa.c					\
		wpa.h					\
		wpa_ctrl.c				\
		wpa_ctrl.h

nm-marshal.h: Makefile.am nm-marshal.list
	$(GLIB_GENMARSHAL) --prefix=nm_marshal $(srcdir)/nm-marshal.list --header > xgen-gmh \
	&& (cmp -s xgen-gmh nm-marshal.h || cp xgen-gmh nm-marshal.h) \
	&& rm -f xgen-gmh xgen-gmh~

nm-marshal.c: Makefile.am nm-marshal.list
	$(GLIB_GENMARSHAL) --prefix=nm_marshal $(srcdir)/nm-marshal.list --body > xgen-gmc \
	&& cp xgen-gmc nm-marshal.c \
	&& rm -f xgen-gmc xgen-gmc~

nm-marshal-main.c: nm-marshal.c nm-marshal.h

built_sources = 					\
	nm-marshal.h					\
	nm-marshal.c					\
	$(NULL)

$(NetworkManager_OBJECTS): $(built_sources)

NetworkManager_CPPFLAGS = 							\
	$(DBUS_CFLAGS)									\
	$(GTHREAD_CFLAGS)								\
	$(HAL_CFLAGS)									\
	$(OPENSSL_CFLAGS)								\
	$(LIBNL_CFLAGS)								\
	-DWPA_SUPPLICANT_BIN=\"$(WPA_SUPPLICANT_BINARY_PATH)\"	\
	-DDBUS_API_SUBJECT_TO_CHANGE						\
	-DG_DISABLE_DEPRECATED							\
	-DBINDIR=\"$(bindir)\"							\
	-DSBINDIR=\"$(sbindir)\"							\
	-DLIBEXECDIR=\"$(libexecdir)\"					\
	-DDATADIR=\"$(datadir)\"							\
	-DSYSCONFDIR=\"$(sysconfdir)\"					\
	-DLOCALSTATEDIR=\"$(localstatedir)\"				\
	-DNM_RUN_DIR=\"$(rundir)\"						\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"				\
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

NetworkManager_LDFLAGS = -rdynamic

libexec_PROGRAMS = nm-crash-logger
nm_crash_logger_SOURCES = nm-crash-logger.c
nm_crash_logger_CPPFLAGS = \
	$(GTHREAD_CFLAGS)								\
	-DG_DISABLE_DEPRECATED							\
	-DBINDIR=\"$(bindir)\"							\
	-DSBINDIR=\"$(sbindir)\"							\
	-DDATADIR=\"$(datadir)\"							\
	-DSYSCONFDIR=\"$(sysconfdir)\"					\
	-DLOCALSTATEDIR=\"$(localstatedir)\"
nm_crash_logger_LDADD = $(GTHREAD_LIBS)


NetworkManagerdir = $(datadir)/NetworkManager
NetworkManager_DATA = gdb-cmd

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = NetworkManager.conf

EXTRA_DIST = \
	$(dbusservice_DATA) \
	$(NetworkManager_DATA) \
	nm-marshal.list

rundir=$(localstatedir)/run/NetworkManager
dispatcherdir=$(sysconfdir)/NetworkManager/dispatcher.d
install-data-hook:
	   $(mkinstalldirs) -m 0700 $(DESTDIR)$(rundir)
	   $(mkinstalldirs) -m 0755 $(DESTDIR)$(dispatcherdir)

CLEANFILES = $(built_sources)

