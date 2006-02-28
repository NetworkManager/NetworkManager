INCLUDES = -I${top_srcdir}/utils -I${top_srcdir}/src -I${top_srcdir}/include

noinst_LTLIBRARIES = libnamed-manager.la

libnamed_manager_la_SOURCES = nm-named-manager.h nm-named-manager.c

libnamed_manager_la_CPPFLAGS = $(DBUS_CFLAGS) $(GTHREAD_CFLAGS) -DNM_PKGDATADIR=\"$(pkgdatadir)\" -DNM_LOCALSTATEDIR=\"$(localstatedir)\" -DDBUS_API_SUBJECT_TO_CHANGE

libnamed_manager_la_LIBADD = $(DBUS_LIBS) $(GTHREAD_LIBS)
