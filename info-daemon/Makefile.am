
INCLUDES =							\
	$(NM_CFLAGS)						\
	$(GLADE_CFLAGS)						\
	$(GCONF_CFLAGS)						\
	-Wall							\
	-DDBUS_API_SUBJECT_TO_CHANGE				\
	-DG_DISABLE_DEPRECATED					\
	-DGTK_DISABLE_DEPRECATED				\
	-DGLADEDIR=\""$(datadir)/NetworkManagerInfo/glade"\"	\
	-DBINDIR=\"$(bindir)\"					\
	-DDATADIR=\"$(datadir)\"

bin_PROGRAMS = NetworkManagerInfo

NetworkManagerInfo_SOURCES =	NetworkManagerInfo.h		\
				NetworkManagerInfo.c		\
				NetworkManagerInfoDbus.h	\
				NetworkManagerInfoDbus.c

NetworkManagerInfo_LDADD = $(NM_LIBS) $(GLADE_LIBS) $(GCONF_LIBS)

gladedir = $(datadir)/NetworkManagerInfo/glade
glade_DATA = passphrase.glade keyring.png

dbusservicedir=$(DBUS_SYS_DIR)
dbusservice_DATA = NetworkManagerInfo.conf

EXTRA_DIST = $(glade_DATA) $(dbusservice_DATA)

