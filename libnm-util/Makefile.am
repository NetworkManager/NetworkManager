INCLUDES = -I${top_srcdir} -I${top_srcdir}/include

lib_LTLIBRARIES=libnm-util.la

libnm_util_la_CPPFLAGS =				\
	$(GLIB_CFLAGS)					\
	$(DBUS_CFLAGS)					\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DG_DISABLE_DEPRECATED			\
	-DGDK_DISABLE_DEPRECATED			\
	-DGNOME_DISABLE_DEPRECATED		\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"

libnm_util_include_HEADERS = 		\
	nm-connection.h			\
	nm-param-spec-specialized.h	\
	nm-setting.h			\
	nm-setting-connection.h		\
	nm-setting-ip4-config.h		\
	nm-setting-ppp.h		\
	nm-setting-serial.h		\
	nm-setting-gsm.h		\
	nm-setting-cdma.h		\
	nm-setting-wired.h		\
	nm-setting-wireless.h		\
	nm-setting-wireless-security.h	\
	nm-setting-vpn.h		\
	nm-setting-vpn-properties.h	\
	nm-utils.h

libnm_util_la_SOURCES=			\
	nm-connection.c			\
	nm-param-spec-specialized.c	\
	nm-setting.c			\
	nm-setting-connection.c		\
	nm-setting-ip4-config.c		\
	nm-setting-ppp.c		\
	nm-setting-serial.c		\
	nm-setting-gsm.c		\
	nm-setting-cdma.c		\
	nm-setting-wired.c		\
	nm-setting-wireless.c		\
	nm-setting-wireless-security.c	\
	nm-setting-vpn.c		\
	nm-setting-vpn-properties.c	\
	nm-utils.c			\
	$(libnm_util_include_HEADERS)

libnm_util_la_LDFLAGS= $(GLIB_LIBS) $(DBUS_LIBS)

libnm_util_la_CFLAGS=-fPIC

libnm_util_includedir=$(includedir)/NetworkManager

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnm-util.pc

DISTCLEANFILES = libnm-util.pc

EXTRA_DIST = libnm-util.pc.in
