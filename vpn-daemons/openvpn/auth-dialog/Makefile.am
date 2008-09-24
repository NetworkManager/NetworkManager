libexec_PROGRAMS = nm-openvpn-auth-dialog

nm_openvpn_auth_dialog_CPPFLAGS =			\
	$(GTHREAD_CFLAGS)			\
	$(GTK_CFLAGS)				\
	$(LIBGNOMEUI_CFLAGS)			\
	$(NETWORK_MANAGER_CFLAGS)		\
	$(GNOMEKEYRING_CFLAGS) \
	-I$(top_srcdir)/
	-DICONDIR=\""$(datadir)/pixmaps"\"	\
	-DGLADEDIR=\""$(gladedir)"\"		\
	-DBINDIR=\""$(bindir)"\"		\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DG_DISABLE_DEPRECATED			\
	-DGDK_DISABLE_DEPRECATED		\
	-DGNOME_DISABLE_DEPRECATED		\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"	\
	-DVERSION=\"$(VERSION)\"			\
	$(NULL)

nm_openvpn_auth_dialog_SOURCES =			\
	main.c					\
	gnome-two-password-dialog.c		\
	gnome-two-password-dialog.h		\
	$(NULL)

nm_openvpn_auth_dialog_LDADD =			\
	$(GTK_LIBS)				\
	$(LIBGNOMEUI_LIBS)			\
	$(top_builddir)/common-gnome/libnm-openvpn-common-gnome.la \
	$(NULL)

CLEANFILES = *~
