INCLUDES = -I${top_srcdir}                       \
           -I${top_srcdir}/include               \
           -I${top_srcdir}/libnm-util            \
           -I${top_srcdir}/src                   \
           -I${top_srcdir}/src/named-manager     \
           -DVPN_NAME_FILES_DIR=\""$(sysconfdir)/NetworkManager/VPN"\"


noinst_LTLIBRARIES = libvpn-manager.la

libvpn_manager_la_SOURCES =	\
	nm-vpn-manager.c	\
	nm-vpn-manager.h	\
	nm-vpn-service.c	\
	nm-vpn-service.h	\
	nm-vpn-connection.c	\
	nm-vpn-connection.h \
	nm-vpn-marshal-main.c

nm-vpn-marshal.h: Makefile.am nm-vpn-marshal.list
	$(GLIB_GENMARSHAL) --prefix=nm_vpn_marshal $(srcdir)/nm-vpn-marshal.list --header > \
		xgen-gmh \
	&& (cmp -s xgen-gmh nm-vpn-marshal.h || cp xgen-gmh nm-vpn-marshal.h) \
	&& rm -f xgen-gmh xgen-gmh~

nm-vpn-marshal.c: Makefile.am nm-vpn-marshal.list
	$(GLIB_GENMARSHAL) --prefix=nm_vpn_marshal $(srcdir)/nm-vpn-marshal.list --body > \
		xgen-gmc \
	&& cp xgen-gmc nm-vpn-marshal.c \
	&& rm -f xgen-gmc xgen-gmc~

nm-vpn-marshal-main.c: nm-vpn-marshal.c nm-vpn-marshal.h

libvpn_manager_la_CPPFLAGS =	\
	$(DBUS_CFLAGS)		\
	-DG_DISABLE_DEPRECATED

libvpn_manager_la_LIBADD =	\
	$(DBUS_LIBS)		\
	$(GTHREAD_LIBS)		\
	$(top_builddir)/libnm-util/libnm-util.la

nm-vpn-manager-glue.h: $(top_srcdir)/introspection/nm-vpn-manager.xml
	dbus-binding-tool --prefix=nm_vpn_manager --mode=glib-server --output=nm-vpn-manager-glue.h $(top_srcdir)/introspection/nm-vpn-manager.xml

nm-vpn-connection-glue.h: $(top_srcdir)/introspection/nm-vpn-connection.xml
	dbus-binding-tool --prefix=nm_vpn_connection --mode=glib-server --output=nm-vpn-connection-glue.h $(top_srcdir)/introspection/nm-vpn-connection.xml

nm-vpn-plugin-bindings.h: $(top_srcdir)/introspection/nm-vpn-plugin.xml
	dbus-binding-tool --prefix=nm_vpn_plugin --mode=glib-client --output=nm-vpn-plugin-bindings.h $(top_srcdir)/introspection/nm-vpn-plugin.xml


built_sources = \
	nm-vpn-manager-glue.h \
	nm-vpn-connection-glue.h \
	nm-vpn-plugin-bindings.h \
	nm-vpn-marshal.h \
	nm-vpn-marshal.c

$(libvpn_manager_la_OBJECTS): $(built_sources)

CLEANFILES = $(built_sources)

EXTRA_DIST = nm-vpn-marshal.list

