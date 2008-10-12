plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-pptp-properties.la

libnm_pptp_properties_la_SOURCES = \
	nm-pptp.c \
	nm-pptp.h \
	advanced-dialog.c \
	advanced-dialog.h \
	import-export.c \
	import-export.h

gladedir = $(datadir)/gnome-vpn-properties/pptp
glade_DATA = nm-pptp-dialog.glade

libnm_pptp_properties_la_CFLAGS =                    \
        $(GLADE_CFLAGS)                                 \
        $(GTK_CFLAGS)                                   \
        $(GCONF_CFLAGS)                                 \
        $(LIBGNOMEUI_CFLAGS)                            \
        $(GNOMEKEYRING_CFLAGS)                          \
        $(NM_UTILS_CFLAGS)                              \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DGLADEDIR=\""$(gladedir)"\"                    \
        -DG_DISABLE_DEPRECATED                          \
        -DGDK_DISABLE_DEPRECATED                        \
        -DGNOME_DISABLE_DEPRECATED                      \
        -DGNOMELOCALEDIR=\"$(datadir)/locale\"          \
        -DVERSION=\"$(VERSION)\"

libnm_pptp_properties_la_LIBADD =    \
        $(GLADE_LIBS)                   \
        $(GTK_LIBS)                     \
        $(GCONF_LIBS)                   \
        $(LIBGNOMEUI_LIBS)              \
        $(top_builddir)/common-gnome/libnm-pptp-common-gnome.la	\
        $(NM_UTILS_LIBS)

libnm_pptp_properties_la_LDFLAGS =   \
        -avoid-version

CLEANFILES = *.bak *.gladep *~

EXTRA_DIST =                            \
        $(glade_DATA)
