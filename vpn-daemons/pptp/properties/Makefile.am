

lib_LTLIBRARIES = libnm-pptp-properties.la

libnm_pptp_properties_la_SOURCES = 			\
				nm-pptp.c

gladedir = $(datadir)/gnome-vpn-properties/pptp
glade_DATA = nm-pptp-dialog.glade

libnm_pptp_properties_la_CFLAGS =                          \
        $(GLADE_CFLAGS)                                 \
        $(GTK_CFLAGS)                                   \
        $(GCONF_CFLAGS)                                 \
        $(LIBGNOMEUI_CFLAGS)                            \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DGLADEDIR=\""$(gladedir)"\"                    \
        -DG_DISABLE_DEPRECATED                          \
        -DGDK_DISABLE_DEPRECATED                        \
        -DGNOME_DISABLE_DEPRECATED                      \
        -DGNOMELOCALEDIR=\""$(prefix)/$(DATADIRNAME)/locale"\"  \
        -DVERSION=\"$(VERSION)\"

libnm_pptp_properties_la_LIBADD =       \
        $(GLADE_LIBS)                   \
        $(GTK_LIBS)                     \
        $(GCONF_LIBS)                   \
        $(LIBGNOMEUI_LIBS)

CLEANFILES = *.bak *.gladep *~

EXTRA_DIST =                            \
        $(glade_DATA)
