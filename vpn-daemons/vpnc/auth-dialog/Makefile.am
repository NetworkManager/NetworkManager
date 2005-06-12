INCLUDES = -I${top_srcdir} -I${top_srcdir}/utils

libexec_PROGRAMS = nm-vpnc-auth-dialog

nm_vpnc_auth_dialog_CPPFLAGS =			\
	$(GTHREAD_CFLAGS)			\
	$(GTK_CFLAGS)				\
	$(LIBGNOMEUI_CFLAGS)			\
	$(GNOMEKEYRING_CFLAGS)			\
	-DICONDIR=\""$(datadir)/pixmaps"\"	\
	-DGLADEDIR=\""$(gladedir)"\"		\
	-DBINDIR=\""$(bindir)"\"		\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DG_DISABLE_DEPRECATED			\
	-DGDK_DISABLE_DEPRECATED		\
	-DGNOME_DISABLE_DEPRECATED		\
	-DGNOMELOCALEDIR=\""$(prefix)/$(DATADIRNAME)/locale"\"	\
	-DVERSION=\"$(VERSION)\"			\
	$(NULL)

nm_vpnc_auth_dialog_SOURCES =			\
	main.c					\
	gnome-two-password-dialog.c		\
	gnome-two-password-dialog.h		\
	$(NULL)

nm_vpnc_auth_dialog_LDADD =			\
	$(GTK_LIBS)				\
	$(LIBGNOMEUI_LIBS)			\
	$(GNOMEKEYRING_LIBS)			\
	$(NULL)

CLEANFILES = *~
