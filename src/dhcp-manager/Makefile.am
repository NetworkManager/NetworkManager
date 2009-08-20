INCLUDES = \
	-I${top_srcdir} \
	-I${top_srcdir}/include \
	-I${top_builddir}/marshallers \
	-I${top_srcdir}/libnm-util \
	-I${top_srcdir}/src \
	-I${top_srcdir}/src/named-manager

noinst_LTLIBRARIES = libdhcp-manager.la

libdhcp_manager_la_SOURCES = \
	nm-dhcp-manager.c \
	nm-dhcp-manager.h \
	nm-dhcp-@DHCP_CLIENT@.c

libdhcp_manager_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DBINDIR=\"$(bindir)\" \
	-DDATADIR=\"$(datadir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DDHCP_CLIENT_PATH=\"$(DHCP_CLIENT_PATH)\"

libdhcp_manager_la_LIBADD = \
	$(top_builddir)/marshallers/libmarshallers.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

EXTRA_DIST = \
	     nm-dhcp-dhclient.c \
	     nm-dhcp-dhcpcd.c
