bin_PROGRAMS = \
	nmcli

INCLUDES = \
	-I${top_srcdir} \
	-I${top_srcdir}/include \
	-I${top_builddir}/marshallers \
	-I${top_srcdir}/libnm-util \
	-I${top_srcdir}/libnm-glib

nmcli_SOURCES = \
	connections.c \
	connections.h \
	devices.c \
	devices.h \
	network-manager.c \
	network-manager.h \
	settings.c \
	settings.h \
	nmcli.c \
	nmcli.h \
	utils.c \
	utils.h

nmcli_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DNMCLI_LOCALEDIR=\"$(datadir)/locale\" \
	-DG_DISABLE_DEPRECATED

nmcli_LDADD = \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(top_builddir)/marshallers/libmarshallers.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib.la


