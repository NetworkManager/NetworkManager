SUBDIRS=. tests

INCLUDES = \
	-I${top_srcdir} \
	-I${top_srcdir}/include \
	-I${top_builddir}/marshallers \
	-I${top_srcdir}/src/logging \
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
	-DG_DISABLE_DEPRECATED \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DDHCLIENT_PATH=\"$(DHCLIENT_PATH)\" \
	-DDHCLIENT_V$(DHCLIENT_VERSION)

libdhcp_dhclient_la_LIBADD = \
	$(top_builddir)/marshallers/libmarshallers.la \
	$(top_builddir)/src/logging/libnm-logging.la \
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
	-DG_DISABLE_DEPRECATED \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DDHCLIENT_PATH=\"$(DHCLIENT_PATH)\" \
	-DDHCPCD_PATH=\"$(DHCPCD_PATH)\"

libdhcp_manager_la_LIBADD = \
	$(top_builddir)/marshallers/libmarshallers.la \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(builddir)/libdhcp-dhclient.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

