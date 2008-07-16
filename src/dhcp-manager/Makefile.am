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
	$(GTHREAD_CFLAGS) \
	$(HAL_CFLAGS) \
	-DDBUS_API_SUBJECT_TO_CHANGE \
	-DG_DISABLE_DEPRECATED \
	-DBINDIR=\"$(bindir)\" \
	-DDATADIR=\"$(datadir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DDHCP_CLIENT_PATH=\"$(DHCP_CLIENT_PATH)\"

libdhcp_manager_la_LIBADD = \
	$(DBUS_LIBS) \
	$(GTHREAD_LIBS) \
	$(top_builddir)/marshallers/libmarshallers.la

EXTRA_DIST = \
	     nm-dhcp-dhclient.c \
	     nm-dhcp-dhcpcd.c
