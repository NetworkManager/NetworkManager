INCLUDES = -I${top_srcdir} -I${top_srcdir}/utils

libexec_PROGRAMS = nm-ppp-auth-dialog-general

nm_ppp_auth_dialog_general_CPPFLAGS =			\
	$(GTHREAD_CFLAGS)			\
	$(GTK_CFLAGS)				\
	$(LIBGNOMEUI_CFLAGS)			\
	$(GNOMEKEYRING_CFLAGS)			\
	-DICONDIR=\""$(datadir)/pixmaps"\"	\
	-DGLADEDIR=\""$(gladedir)"\"		\
    -DAUTH_MODULES_DIR=\""$(libgenericauthmodulesdir)"\"                    \
	-DBINDIR=\""$(bindir)"\"		\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DG_DISABLE_DEPRECATED			\
	-DGDK_DISABLE_DEPRECATED		\
	-DGNOME_DISABLE_DEPRECATED		\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"	\
	-DVERSION=\"$(VERSION)\"			\
	$(NULL)

nm_ppp_auth_dialog_general_SOURCES =			\
	main.c					\
	gnome-generic-auth-dialog.c		\
	gnome-generic-auth-dialog.h		\
	$(NULL)

nm_ppp_auth_dialog_general_LDADD =			\
	$(GTK_LIBS)				\
	$(LIBGNOMEUI_LIBS)			\
	$(GNOMEKEYRING_LIBS)			\
	$(NULL)

libgenericauthmodulesdir=$(libdir)/NetworkManager/gnome-generic-auth
libgenericauthmodules_LTLIBRARIES = \
          libanonymous-auth-module.la \
          libchap-auth-module.la \
          libmschapv2-auth-module.la

libanonymous_auth_module_la_SOURCES = 			\
				anonymous-auth-module.c

libmschapv2_auth_module_la_SOURCES = 			\
				mschapv2-auth-module.c

libchap_auth_module_la_SOURCES = 			\
				chap-auth-module.c

gladedir = $(datadir)/gnome-generic-auth
glade_DATA = nm-ppp-auth.glade

libanonymous_auth_module_la_CFLAGS =                          \
        $(GLADE_CFLAGS)                                 \
        $(GTK_CFLAGS)                                   \
        $(GCONF_CFLAGS)                                 \
        $(LIBGNOMEUI_CFLAGS)                            \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DGLADEDIR=\""$(gladedir)"\"                    \
        -DAUTH_MODULES_DIR=\""$(libgenericauthmodulesdir)"\"                    \
        -DG_DISABLE_DEPRECATED                          \
        -DGDK_DISABLE_DEPRECATED                        \
        -DGNOME_DISABLE_DEPRECATED                      \
	    -DGNOMELOCALEDIR=\"$(datadir)/locale\"		\
        -DVERSION=\"$(VERSION)\"

libanonymous_auth_module_la_LIBADD =       \
        $(GLADE_LIBS)                   \
        $(GTK_LIBS)                     \
        $(GCONF_LIBS)                   \
        $(LIBGNOMEUI_LIBS)

libchap_auth_module_la_CFLAGS =                          \
        $(GLADE_CFLAGS)                                 \
        $(GTK_CFLAGS)                                   \
        $(GCONF_CFLAGS)                                 \
        $(LIBGNOMEUI_CFLAGS)                            \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DGLADEDIR=\""$(gladedir)"\"                    \
        -DAUTH_MODULES_DIR=\""$(libgenericauthmodulesdir)"\"                    \
        -DG_DISABLE_DEPRECATED                          \
        -DGDK_DISABLE_DEPRECATED                        \
        -DGNOME_DISABLE_DEPRECATED                      \
	    -DGNOMELOCALEDIR=\"$(datadir)/locale\"		\
        -DVERSION=\"$(VERSION)\"

libmschapv2_auth_module_la_CFLAGS =                          \
        $(GLADE_CFLAGS)                                 \
        $(GTK_CFLAGS)                                   \
        $(GCONF_CFLAGS)                                 \
        $(LIBGNOMEUI_CFLAGS)                            \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DGLADEDIR=\""$(gladedir)"\"                    \
        -DAUTH_MODULES_DIR=\""$(libgenericauthmodulesdir)"\"                    \
        -DG_DISABLE_DEPRECATED                          \
        -DGDK_DISABLE_DEPRECATED                        \
        -DGNOME_DISABLE_DEPRECATED                      \
	    -DGNOMELOCALEDIR=\"$(datadir)/locale\"		\
        -DVERSION=\"$(VERSION)\"

libchap_auth_module_la_LIBADD =       \
        $(GLADE_LIBS)                   \
        $(GTK_LIBS)                     \
        $(GCONF_LIBS)                   \
        $(LIBGNOMEUI_LIBS)

libmschapv2_auth_module_la_LIBADD =       \
        $(GLADE_LIBS)                   \
        $(GTK_LIBS)                     \
        $(GCONF_LIBS)                   \
        $(LIBGNOMEUI_LIBS)

EXTRA_DIST =                            \
        $(glade_DATA)

CLEANFILES = *.bak *.gladep *~
