noinst_LTLIBRARIES = libmarshallers.la

BUILT_SOURCES = \
	nm-marshal.h \
	nm-marshal.c

libmarshallers_la_SOURCES = \
	nm-marshal-main.c

libmarshallers_la_CPPFLAGS = \
	$(GTHREAD_CFLAGS) \
	-DG_DISABLE_DEPRECATED


libmarshallers_la_LIBADD = $(GTHREAD_LIBS)

EXTRA_DIST = nm-marshal.list
CLEANFILES = $(BUILT_SOURCES)

nm-marshal.h: nm-marshal.list
	$(GLIB_GENMARSHAL) $< --prefix=nm_marshal --header > $@

nm-marshal.c: nm-marshal.list
	$(GLIB_GENMARSHAL) $< --prefix=nm_marshal --body > $@

nm-marshal-main.c: nm-marshal.c nm-marshal.h

