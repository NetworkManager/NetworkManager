SUBDIRS = . tests

INCLUDES = \
	-I${top_srcdir} \
	-I${top_builddir}/include \
	-I${top_srcdir}/include \
	-I${top_builddir}/src/generated \
	-I${top_srcdir}/src/generated \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/src/posix-signals \
	-I${top_builddir}/libnm-util \
	-I${top_srcdir}/libnm-util \
	-I${top_srcdir}/src

noinst_LTLIBRARIES = libdhcp-manager.la libdhcp-dhclient.la

################## dhclient ##################

libdhcp_dhclient_la_SOURCES = \
	nm-dhcp-dhclient-utils.h \
	nm-dhcp-dhclient-utils.c \
	nm-dhcp-dhclient.h \
	nm-dhcp-dhclient.c

libdhcp_dhclient_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DDHCLIENT_PATH=\"$(DHCLIENT_PATH)\" \
	-DNMSTATEDIR=\"$(nmstatedir)\" \
	-DNMCONFDIR=\"$(nmconfdir)\"

libdhcp_dhclient_la_LIBADD = \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(top_builddir)/src/posix-signals/libnm-posix-signals.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

################## main lib ##################

libdhcp_manager_la_SOURCES = \
	nm-dhcp-client.c \
	nm-dhcp-client.h \
	nm-dhcp-manager.c \
	nm-dhcp-manager.h \
	nm-dhcp-dhcpcd.h \
	nm-dhcp-dhcpcd.c

libdhcp_manager_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DDHCLIENT_PATH=\"$(DHCLIENT_PATH)\" \
	-DDHCPCD_PATH=\"$(DHCPCD_PATH)\" \
	-DNMSTATEDIR=\"$(nmstatedir)\"

libdhcp_manager_la_LIBADD = \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(top_builddir)/src/posix-signals/libnm-posix-signals.la \
	$(builddir)/libdhcp-dhclient.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

