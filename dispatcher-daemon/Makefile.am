INCLUDES =						\
	$(DBUS_CFLAGS)					\
	$(GTHREAD_CFLAGS)				\
	-Wall						\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

bin_PROGRAMS = NetworkManagerDispatcher

NetworkManagerDispatcher_SOURCES =	NetworkManagerDispatcher.c

NetworkManagerDispatcher_LDADD = $(DBUS_LIBS) $(GTHREAD_LIBS)

