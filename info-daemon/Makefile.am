INCLUDES =						\
	$(NM_CFLAGS)					\
	$(GLADE_CFLAGS)				\
	-Wall						\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

bin_PROGRAMS = NetworkManagerInfo

NetworkManagerInfo_SOURCES =	NetworkManagerInfo.c			\
						NetworkManagerInfoDbus.c

NetworkManagerInfo_LDADD = $(NM_LIBS) $(GLADE_LIBS)

