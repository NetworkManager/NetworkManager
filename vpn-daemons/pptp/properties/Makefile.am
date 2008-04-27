

lib_LTLIBRARIES = libnm-ppp-properties.la

libnm_ppp_properties_la_SOURCES = 			\
				nm-ppp-properties.c \
                vpnui_impl.c \
                vpnui_expand.c \
                vpnui_opt.c \
                vpnui_validate.c \
                vpnui_variant.c  \
                util_lists.c \
                vpnui_impl.h \
                vpnui_opt.h  \
                vpnui_expand.h \
                vpnui_validate.h \
                vpnui_variant.h  \
                util_lists.h \
                vpnui_impl.h 

gladedir = $(datadir)/gnome-vpn-properties/ppp
glade_DATA = nm-ppp-dialog.glade

libnm_ppp_properties_la_CFLAGS =                        \
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

libnm_ppp_properties_la_LIBADD =        \
        $(GLADE_LIBS)                   \
        $(GTK_LIBS)                     \
        $(GCONF_LIBS)                   \
        $(LIBGNOMEUI_LIBS)              \
        $(NETWORK_MANAGER_LIBS)

libnm_ppp_properties_la_LDFLAGS =       \
        -avoid-version

CLEANFILES = *.bak *.gladep *~

EXTRA_DIST =                            \
        $(glade_DATA)
