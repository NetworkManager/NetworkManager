

lib_LTLIBRARIES = libnm-vpnc-properties.la

libnm_vpnc_properties_la_SOURCES = 			\
				nm-vpnc.c

gladedir = $(datadir)/gnome-vpn-properties/vpnc
glade_DATA = nm-vpnc-dialog.glade

libnm_vpnc_properties_la_CFLAGS =                       \
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
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"		\
        -DVERSION=\"$(VERSION)\"

libnm_vpnc_properties_la_LIBADD =       \
        $(GLADE_LIBS)                   \
        $(GTK_LIBS)                     \
        $(GCONF_LIBS)                   \
        $(LIBGNOMEUI_LIBS)              \
        $(NETWORK_MANAGER_LIBS)

CLEANFILES = *.bak *.gladep *~

EXTRA_DIST =                            \
        $(glade_DATA)
