INCLUDES =						\
	$(NM_CFLAGS)					\
	$(GLADE_CFLAGS)				\
	$(GCONF_CFLAGS)
	-Wall						\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DG_DISABLE_DEPRECATED			\
	-DGTK_DISABLE_DEPRECATED			\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

bin_PROGRAMS = NetworkManagerInfo

NetworkManagerInfo_SOURCES =	NetworkManagerInfo.c			\
						NetworkManagerInfoDbus.c

NetworkManagerInfo_LDADD = $(NM_LIBS) $(GLADE_LIBS) $(GCONF_LIBS)

