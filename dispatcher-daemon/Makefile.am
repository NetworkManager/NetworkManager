INCLUDES = 					   \
	$(NM_CFLAGS) 			   \
	-DDBUS_API_SUBJECT_TO_CHANGE		   \
	-DBINDIR=\"$(bindir)\"			   \
	-DDATADIR=\"$(datadir)\"

bin_PROGRAMS = NetworkManagerDispatcher

NetworkManagerDispatcher_SOURCES =	NetworkManagerDispatcher.c

NetworkManagerDispatcher_LDADD = $(NM_LIBS)

