INCLUDES = \
	-I${top_srcdir} \
	-I${top_srcdir}/include \
	-I${top_srcdir}/libnm-util \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/src \
	-I${top_builddir}/marshallers \
	-I${top_srcdir}/src/named-manager \
	-DVPN_NAME_FILES_DIR=\""$(sysconfdir)/NetworkManager/VPN"\"


noinst_LTLIBRARIES = libvpn-manager.la

libvpn_manager_la_SOURCES =	\
	nm-vpn-manager.c	\
	nm-vpn-manager.h	\
	nm-vpn-service.c	\
	nm-vpn-service.h	\
	nm-vpn-connection.c	\
	nm-vpn-connection.h

libvpn_manager_la_CPPFLAGS =	\
	$(DBUS_CFLAGS)		\
	$(GLIB_CFLAGS)		\
	-DG_DISABLE_DEPRECATED

libvpn_manager_la_LIBADD = \
	$(top_builddir)/marshallers/libmarshallers.la \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

nm-vpn-connection-glue.h: $(top_srcdir)/introspection/nm-vpn-connection.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_vpn_connection --mode=glib-server --output=$@ $<

nm-vpn-plugin-bindings.h: $(top_srcdir)/introspection/nm-vpn-plugin.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_vpn_plugin --mode=glib-client --output=$@ $<


BUILT_SOURCES = \
	nm-vpn-connection-glue.h \
	nm-vpn-plugin-bindings.h

CLEANFILES = $(BUILT_SOURCES)

