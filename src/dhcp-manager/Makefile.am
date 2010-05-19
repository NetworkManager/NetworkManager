INCLUDES = \
	-I${top_srcdir} \
	-I${top_srcdir}/include \
	-I${top_builddir}/marshallers \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/libnm-util \
	-I${top_srcdir}/src \
	-I${top_srcdir}/src/named-manager

noinst_LTLIBRARIES = libdhcp-manager.la

libdhcp_manager_la_SOURCES = \
	nm-dhcp-client.c \
	nm-dhcp-client.h \
	nm-dhcp-manager.c \
	nm-dhcp-manager.h \
	nm-dhcp-dhclient.h \
	nm-dhcp-dhclient.c \
	nm-dhcp-dhcpcd.h \
	nm-dhcp-dhcpcd.c

libdhcp_manager_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DBINDIR=\"$(bindir)\" \
	-DDATADIR=\"$(datadir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DDHCLIENT_PATH=\"$(DHCLIENT_PATH)\" \
	-DDHCPCD_PATH=\"$(DHCPCD_PATH)\"

libdhcp_manager_la_LIBADD = \
	$(top_builddir)/marshallers/libmarshallers.la \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

