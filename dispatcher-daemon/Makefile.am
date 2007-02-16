INCLUDES = -I${top_srcdir} -I${top_srcdir}/utils -I${top_srcdir}/include

NULL=

sbin_PROGRAMS = NetworkManagerDispatcher

NetworkManagerDispatcher_CPPFLAGS = 		\
	$(DBUS_CFLAGS)						\
	$(GTHREAD_CFLAGS)					\
	-I$(top_builddir)/libnm-glib \
	-Wall							\
	-DDBUS_API_SUBJECT_TO_CHANGE			\
	-DBINDIR=\"$(bindir)\"				\
	-DDATADIR=\"$(datadir)\"				\
	-DSYSCONFDIR=\"$(sysconfdir)\"		\
	-DLOCALSTATEDIR=\"$(localstatedir)\"	\
	$(NULL)

NetworkManagerDispatcher_SOURCES =	NetworkManagerDispatcher.c

NetworkManagerDispatcher_LDADD =		\
	$(DBUS_LIBS)	\
	$(GTHREAD_LIBS)	\
	$(top_builddir)/utils/libnmutils.la \
	$(top_builddir)/libnm-glib/libnm-glib.la

