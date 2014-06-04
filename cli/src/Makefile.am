bin_PROGRAMS = \
	nmcli

AM_CPPFLAGS = \
	-I${top_srcdir} \
	-I${top_srcdir}/include \
	-I${top_builddir}/include \
	-I${top_srcdir}/libnm-util \
	-I${top_builddir}/libnm-util \
	-I${top_srcdir}/libnm-glib \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DG_LOG_DOMAIN=\""nmcli"\" \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DNMCLI_LOCALEDIR=\"$(datadir)/locale\"

nmcli_SOURCES = \
	common.c \
	common.h \
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

nmcli_LDADD = \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(READLINE_LIBS) \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib.la


