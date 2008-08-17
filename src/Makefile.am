SUBDIRS= \
	named-manager \
	vpn-manager \
	dhcp-manager \
	supplicant-manager \
	ppp-manager \
	backends \
	dnsmasq-manager

INCLUDES = -I${top_srcdir}                   \
           -I${top_srcdir}/include           \
           -I${top_builddir}/marshallers   \
           -I${top_srcdir}/src/named-manager \
           -I${top_srcdir}/src/vpn-manager   \
           -I${top_srcdir}/src/dhcp-manager  \
           -I${top_srcdir}/src/supplicant-manager  \
           -I${top_srcdir}/src/dnsmasq-manager  \
           -I${top_srcdir}/libnm-util \
           -I${top_srcdir}/callouts

sbin_PROGRAMS = NetworkManager

NetworkManager_SOURCES =				\
		nm-call-store.c				\
		nm-call-store.h				\
		nm-device.c				\
		nm-device.h				\
		nm-device-interface.c			\
		nm-device-interface.h			\
		nm-device-private.h			\
		nm-device-ethernet.c	\
		nm-device-ethernet.h	\
		nm-device-wifi.c	\
		nm-device-wifi.h	\
		NetworkManagerAP.c			\
		NetworkManagerAP.h			\
		nm-dbus-manager.h			\
		nm-dbus-manager.c			\
		nm-hal-manager.c			\
		nm-hal-manager.h			\
		nm-ip4-config.c			\
		nm-ip4-config.h			\
		nm-active-connection.h \
		nm-active-connection.c \
		NetworkManager.c			\
		NetworkManagerPolicy.c		\
		NetworkManagerPolicy.h		\
		NetworkManagerUtils.c		\
		NetworkManagerUtils.h		\
		NetworkManagerSystem.c		\
		NetworkManagerSystem.h		\
		nm-logging.c				\
		nm-logging.h				\
		nm-manager.c				\
		nm-manager.h				\
		nm-netlink-monitor.c		\
		nm-netlink-monitor.h		\
		nm-activation-request.c		\
		nm-activation-request.h		\
		nm-properties-changed-signal.c	\
		nm-properties-changed-signal.h	\
		nm-serial-device.c		\
		nm-serial-device.h		\
		nm-gsm-device.c		\
		nm-gsm-device.h		\
		nm-cdma-device.c		\
		nm-cdma-device.h		\
		nm-hso-gsm-device.c \
		nm-hso-gsm-device.h \
		wpa.c				\
		wpa.h				\
		nm-netlink.c			\
		nm-netlink.h \
		nm-dhcp4-config.c \
		nm-dhcp4-config.h

nm-access-point-glue.h: $(top_srcdir)/introspection/nm-access-point.xml
	dbus-binding-tool --prefix=nm_access_point --mode=glib-server --output=$@ $<

nm-manager-glue.h: $(top_srcdir)/introspection/nm-manager.xml
	dbus-binding-tool --prefix=nm_manager --mode=glib-server --output=$@ $<

nm-device-interface-glue.h: $(top_srcdir)/introspection/nm-device.xml
	dbus-binding-tool --prefix=nm_device_interface --mode=glib-server --output=$@ $<

nm-device-ethernet-glue.h: $(top_srcdir)/introspection/nm-device-ethernet.xml
	dbus-binding-tool --prefix=nm_device_ethernet --mode=glib-server --output=$@ $<

nm-device-wifi-glue.h: $(top_srcdir)/introspection/nm-device-wifi.xml
	dbus-binding-tool --prefix=nm_device_wifi --mode=glib-server --output=$@ $<

nm-serial-device-glue.h: $(top_srcdir)/introspection/nm-device-serial.xml
	dbus-binding-tool --prefix=nm_serial_device --mode=glib-server --output=$@ $<

nm-cdma-device-glue.h: $(top_srcdir)/introspection/nm-device-cdma.xml
	dbus-binding-tool --prefix=nm_cdma_device --mode=glib-server --output=$@ $<

nm-gsm-device-glue.h: $(top_srcdir)/introspection/nm-device-gsm.xml
	dbus-binding-tool --prefix=nm_gsm_device --mode=glib-server --output=$@ $<

nm-ip4-config-glue.h: $(top_srcdir)/introspection/nm-ip4-config.xml
	dbus-binding-tool --prefix=nm_ip4_config --mode=glib-server --output=$@ $<

nm-active-connection-glue.h: $(top_srcdir)/introspection/nm-active-connection.xml
	dbus-binding-tool --prefix=nm_active_connection --mode=glib-server --output=$@ $<

nm-dhcp4-config-glue.h: $(top_srcdir)/introspection/nm-dhcp4-config.xml
	dbus-binding-tool --prefix=nm_dhcp4_config --mode=glib-server --output=$@ $<

BUILT_SOURCES = 					\
	nm-access-point-glue.h				\
	nm-manager-glue.h				\
	nm-device-interface-glue.h			\
	nm-device-ethernet-glue.h			\
	nm-device-wifi-glue.h		\
	nm-serial-device-glue.h \
	nm-cdma-device-glue.h \
	nm-gsm-device-glue.h \
	nm-ip4-config-glue.h				\
	nm-active-connection-glue.h \
	nm-dhcp4-config-glue.h

NetworkManager_CPPFLAGS = 							\
	$(DBUS_CFLAGS)									\
	$(GTHREAD_CFLAGS)								\
	$(HAL_CFLAGS)									\
	$(OPENSSL_CFLAGS)								\
	$(LIBNL_CFLAGS)								\
	-DDBUS_API_SUBJECT_TO_CHANGE						\
	-DG_DISABLE_DEPRECATED							\
	-DBINDIR=\"$(bindir)\"							\
	-DSBINDIR=\"$(sbindir)\"							\
	-DLIBEXECDIR=\"$(libexecdir)\"					\
	-DDATADIR=\"$(datadir)\"							\
	-DSYSCONFDIR=\"$(sysconfdir)\"					\
	-DLOCALSTATEDIR=\"$(localstatedir)\"				\
	-DNM_RUN_DIR=\"$(rundir)\"						\
	-DNMLOCALEDIR=\"$(datadir)/locale\"				\
	-DARP_DEBUG

NetworkManager_LDADD = 							\
			$(DBUS_LIBS)						\
			$(GTHREAD_LIBS)					\
			$(HAL_LIBS)						\
			$(LIBNL_LIBS)						\
			$(top_builddir)/marshallers/libmarshallers.la	\
			./named-manager/libnamed-manager.la	\
			./vpn-manager/libvpn-manager.la		\
			./dhcp-manager/libdhcp-manager.la		\
			./supplicant-manager/libsupplicant-manager.la		\
			./dnsmasq-manager/libdnsmasq-manager.la		\
			./ppp-manager/libppp-manager.la		\
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
	$(NetworkManager_DATA)

rundir=$(localstatedir)/run/NetworkManager
install-data-hook:
	$(mkinstalldirs) -m 0700 $(DESTDIR)$(rundir)

CLEANFILES = $(BUILT_SOURCES)

