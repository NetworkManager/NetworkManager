noinst_LTLIBRARIES = libmarshallers.la

BUILT_SOURCES = \
	nm-marshal.h \
	nm-marshal.c

libmarshallers_la_SOURCES = \
	nm-marshal-main.c

libmarshallers_la_CPPFLAGS = \
	$(GTHREAD_CFLAGS) \
	-g \
	-Wall \
	-DG_DISABLE_DEPRECATED


libmarshallers_la_LIBADD = $(GTHREAD_LIBS)

EXTRA_DIST = nm-marshal.list
CLEANFILES = $(BUILT_SOURCES)

nm-marshal.h: nm-marshal.list
	$(GLIB_GENMARSHAL) --prefix=nm_marshal $(srcdir)/nm-marshal.list --header > \
		xgen-gmh \
	&& (cmp -s xgen-gmh nm-marshal.h || cp xgen-gmh nm-marshal.h) \
	&& rm -f xgen-gmh xgen-gmh~

nm-marshal.c: nm-marshal.list
	$(GLIB_GENMARSHAL) --prefix=nm_marshal $(srcdir)/nm-marshal.list --body > \
		xgen-gmc \
	&& cp xgen-gmc nm-marshal.c \
	&& rm -f xgen-gmc xgen-gmc~

nm-marshal-main.c: nm-marshal.c nm-marshal.h

