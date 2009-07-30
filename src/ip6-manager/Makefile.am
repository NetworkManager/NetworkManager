INCLUDES = \
	-I${top_srcdir} \
	-I${top_srcdir}/include \
	-I${top_builddir}/marshallers \
	-I${top_srcdir}/libnm-util \
	-I${top_srcdir}/src \
	-I${top_srcdir}/src/named-manager

noinst_LTLIBRARIES = libip6-manager.la

libip6_manager_la_SOURCES = \
	nm-ip6-manager.c \
	nm-ip6-manager.h \
	nm-netlink-listener.c \
	nm-netlink-listener.h

libip6_manager_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(HAL_CFLAGS) \
	-DG_DISABLE_DEPRECATED

libip6_manager_la_LIBADD = \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(top_builddir)/marshallers/libmarshallers.la
