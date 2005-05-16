INCLUDES = -I${top_srcdir} -I${top_srcdir}/utils
NULL=

bin_PROGRAMS = NetworkManagerDispatcher

NetworkManagerDispatcher_CPPFLAGS = 	\
	$(DBUS_CFLAGS)					\
	$(GTHREAD_CFLAGS)				\
	-Wall						\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"		\
	$(NULL)

NetworkManagerDispatcher_SOURCES =	NetworkManagerDispatcher.c

NetworkManagerDispatcher_LDADD =		\
				$(DBUS_LIBS)	\
				$(GTHREAD_LIBS)	\
				$(top_builddir)/utils/libnmutils.la


