
bin_PROGRAMS = nm-vpn-properties

nm_vpn_propertiesdir=$(includedir)/NetworkManager

nm_vpn_properties_HEADERS = 					\
	nm-vpn-ui-interface.h

nm_vpn_properties_SOURCES = 					\
					nm-vpn-properties.c		\
					clipboard.c			\
					clipboard.h			\
					nm-vpn-ui-interface.h

gladedir = $(datadir)/gnome-vpn-properties
glade_DATA = nm-vpn-properties.glade

nm_vpn_properties_CFLAGS =                              \
        $(GLADE_CFLAGS)                                 \
        $(GTK_CFLAGS)                                   \
        $(GCONF_CFLAGS)                                 \
        $(GMODULE_CFLAGS)                               \
        $(LIBGNOMEUI_CFLAGS)                            \
        -DSYSCONFDIR=\"$(sysconfdir)\"			\
        -DICONDIR=\""$(datadir)/icons"\"                \
        -DGLADEDIR=\""$(gladedir)"\"                    \
        -DG_DISABLE_DEPRECATED                          \
        -DGDK_DISABLE_DEPRECATED                        \
        -DGNOME_DISABLE_DEPRECATED                      \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"		\
        -DVERSION=\"$(VERSION)\" \
        $(NULL)

nm_vpn_properties_LDADD =               \
        $(GLADE_LIBS)                   \
        $(GTK_LIBS)                     \
        $(GCONF_LIBS)                   \
        $(GMODULE_LIBS)                 \
        $(LIBGNOMEUI_LIBS)              \
        $(NULL)

CLEANFILES = $(server_DATA) *.bak *.gladep *~

EXTRA_DIST =                            \
        $(glade_DATA)                   \
        $(NULL)



