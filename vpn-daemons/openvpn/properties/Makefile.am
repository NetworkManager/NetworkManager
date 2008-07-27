plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-openvpn-properties.la

libnm_openvpn_properties_la_SOURCES = \
	nm-openvpn.c \
	nm-openvpn.h \
	auth-helpers.c \
	auth-helpers.h \
	import-export.c \
	import-export.h

gladedir = $(datadir)/gnome-vpn-properties/openvpn
glade_DATA = nm-openvpn-dialog.glade

libnm_openvpn_properties_la_CFLAGS =                    \
        $(GLADE_CFLAGS)                                 \
        $(GTK_CFLAGS)                                   \
        $(GCONF_CFLAGS)                                 \
        $(LIBGNOMEUI_CFLAGS)                            \
        $(NETWORK_MANAGER_CFLAGS)                       \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DGLADEDIR=\""$(gladedir)"\"                    \
        -DG_DISABLE_DEPRECATED                          \
        -DGDK_DISABLE_DEPRECATED                        \
        -DGNOME_DISABLE_DEPRECATED                      \
        -DGNOMELOCALEDIR=\"$(datadir)/locale\"          \
        -DVERSION=\"$(VERSION)\"

libnm_openvpn_properties_la_LIBADD =    \
        $(GLADE_LIBS)                   \
        $(GTK_LIBS)                     \
        $(GCONF_LIBS)                   \
        $(LIBGNOMEUI_LIBS)              \
        $(NETWORK_MANAGER_LIBS)

libnm_openvpn_properties_la_LDFLAGS =   \
        -avoid-version

CLEANFILES = *.bak *.gladep *~

EXTRA_DIST =                            \
        $(glade_DATA)
