NULL=
INCLUDES = -I${top_srcdir} -I${top_srcdir}/src

noinst_LTLIBRARIES = libnmutils.la

libnmutils_la_CFLAGS = 		\
	$(DBUS_CFLAGS)					\
	$(GTHREAD_CFLAGS)				\
	$(DBUS_GLIB_CFLAGS)				\
	-DDBUS_API_SUBJECT_TO_CHANGE			\
	-DG_DISABLE_DEPRECATED				\
	-DGDK_DISABLE_DEPRECATED			\
	-DGNOME_DISABLE_DEPRECATED			\
	$(NULL)

libnmutils_la_SOURCES = 	            \
	nm-utils.c           \
	nm-utils.h           \
	$(NULL)
