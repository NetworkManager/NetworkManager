## Process this file with automake to produce Makefile.in

NULL=

INCLUDES = 							\
	$(NM_CFLAGS)						\
	$(GLADE_CFLAGS)					\
	$(DBUS_CFLAGS)						\
	$(DBUS_GLIB_CFLAGS)					\
	$(PANEL_APPLET_CFLAGS)				\
	-DICONDIR=\""$(datadir)/pixmaps"\"		\
	-DG_DISABLE_DEPRECATED				\
	-DGDK_DISABLE_DEPRECATED				\
	-DGNOME_DISABLE_DEPRECATED			\
	$(NULL)

libexec_PROGRAMS = NMWirelessApplet

NMWirelessApplet_SOURCES =		\
	NMWirelessApplet.c			\
	NMWirelessApplet.h			\
	NMWirelessAppletDbus.c		\
	NMWirelessAppletDbus.h		\
	$(NULL)

NMWirelessApplet_LDADD =		\
	$(NM_LIBS)			\
	$(LIBGLADE_LIBS)		\
	$(DBUS_LIBS)			\
	$(DBUS_GLIB_LIBS)		\
	$(PANEL_APPLET_LIBS)	\
	$(NULL)

serverdir          = $(libdir)/bonobo/servers
server_in_files    = NMWirelessApplet.server.in
server_DATA        = $(server_in_files:.server.in=.server)

$(server_in_files:.server.in=.server): $(server_in_files)
	sed -e "s|\@LIBEXECDIR\@|$(libexecdir)|" $< > $@

uidir = $(datadir)/gnome-2.0/ui
ui_DATA = NMWirelessApplet.xml

pixmapdir = $(datadir)/pixmaps/NMWirelessApplet
pixmap_DATA = no-link-0.png	\
	broken-0.png		\
	signal-1-40.png		\
	signal-41-60.png	\
	signal-61-80.png	\
	signal-81-100.png	\
	wireless-applet.png	\
	connect-0.png		\
	connect-1.png		\
	connect-2.png		\
	connect-3.png		\
	keyring.png		\
	$(NULL)

CLEANFILES = $(server_in_files) $(server_DATA) *.bak *.gladep

EXTRA_DIST = 				\
	$(server_DATA)			\
	$(pixmap_DATA)			\
	$(ui_DATA)			\
	$(NULL)

