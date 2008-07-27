plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpnc-properties.la

libnm_vpnc_properties_la_SOURCES = \
	pcf-file.c \
	pcf-file.h \
	nm-vpnc.c \
	nm-vpnc.h

gladedir = $(datadir)/gnome-vpn-properties/vpnc
glade_DATA = nm-vpnc-dialog.glade

libnm_vpnc_properties_la_CFLAGS =                          \
        $(GLADE_CFLAGS)                                 \
        $(GTK_CFLAGS)                                   \
        $(GCONF_CFLAGS)                                 \
        $(LIBGNOMEUI_CFLAGS)                            \
        $(NM_UTILS_CFLAGS)                              \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DGLADEDIR=\""$(gladedir)"\"                    \
        -DG_DISABLE_DEPRECATED                          \
        -DGDK_DISABLE_DEPRECATED                        \
        -DGNOME_DISABLE_DEPRECATED                      \
        -DGNOMELOCALEDIR=\"$(datadir)/locale\"		\
        -DVERSION=\"$(VERSION)\"

libnm_vpnc_properties_la_LIBADD = \
        $(GLADE_LIBS) \
        $(GTK_LIBS) \
        $(GCONF_LIBS) \
        $(LIBGNOMEUI_LIBS) \
        $(NM_UTILS_LIBS)

libnm_vpnc_properties_la_LDFLAGS =      \
        -avoid-version

CLEANFILES = *.bak *.gladep *~

EXTRA_DIST =                            \
        $(glade_DATA)
