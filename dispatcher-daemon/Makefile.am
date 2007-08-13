NULL=

sbin_PROGRAMS = NetworkManagerDispatcher

NetworkManagerDispatcher_SOURCES =		\
	NetworkManagerDispatcher.c		\
	$(NULL)

NetworkManagerDispatcher_CPPFLAGS = 		\
	-I$(top_srcdir)				\
	-I$(top_srcdir)/utils			\
	-I$(top_srcdir)/include			\
	-I$(top_srcdir)/libnm-util		\
	-I$(top_srcdir)/libnm-glib		\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"		\
	-DSYSCONFDIR=\"$(sysconfdir)\"		\
	-DLOCALSTATEDIR=\"$(localstatedir)\"	\
	$(NULL)

NetworkManagerDispatcher_CFLAGS = 		\
	$(DBUS_CFLAGS)				\
	$(GTHREAD_CFLAGS)			\
	-Wall					\
	$(NULL)

NetworkManagerDispatcher_LDADD =		\
	$(top_builddir)/utils/libnmutils.la	\
	$(top_builddir)/libnm-util/libnm-util.la\
	$(top_builddir)/libnm-glib/libnm_glib.la\
	$(DBUS_LIBS)				\
	$(GTHREAD_LIBS)				\
	$(NULL)
