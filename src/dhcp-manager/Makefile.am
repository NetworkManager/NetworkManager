INCLUDES = -I${top_srcdir}                       \
           -I${top_srcdir}/include               \
           -I${top_srcdir}/utils                 \
           -I${top_srcdir}/src                   \
           -I${top_srcdir}/src/named-manager

noinst_LTLIBRARIES = libdhcp-manager.la

BUILT_SOURCES = \
	nm-dhcp-marshal.h \
	nm-dhcp-marshal.c

libdhcp_manager_la_SOURCES = \
	nm-dhcp-manager.c \
	nm-dhcp-manager.h \
	nm-dhcp-marshal-main.c

libdhcp_manager_la_CPPFLAGS =	$(DBUS_CFLAGS)					\
						$(GTHREAD_CFLAGS)				\
						$(HAL_CFLAGS)					\
						-g							\
						-Wall						\
						-DDBUS_API_SUBJECT_TO_CHANGE		\
						-DG_DISABLE_DEPRECATED			\
						-DBINDIR=\"$(bindir)\"			\
						-DDATADIR=\"$(datadir)\"			\
						-DSYSCONFDIR=\"$(sysconfdir)\"


libdhcp_manager_la_LIBADD = $(DBUS_LIBS) $(GTHREAD_LIBS)

EXTRA_DIST = nm-dhcp-marshal.list
CLEANFILES = $(BUILT_SOURCES)

nm-dhcp-marshal.h: nm-dhcp-marshal.list
	$(GLIB_GENMARSHAL) --prefix=nm_dhcp_marshal $(srcdir)/nm-dhcp-marshal.list --header > \
		xgen-gmh \
	&& (cmp -s xgen-gmh nm-dhcp-marshal.h || cp xgen-gmh nm-dhcp-marshal.h) \
	&& rm -f xgen-gmh xgen-gmh~

nm-dhcp-marshal.c: nm-dhcp-marshal.list
	$(GLIB_GENMARSHAL) --prefix=nm_dhcp_marshal $(srcdir)/nm-dhcp-marshal.list --body > \
		xgen-gmc \
	&& cp xgen-gmc nm-dhcp-marshal.c \
	&& rm -f xgen-gmc xgen-gmc~

nm-dhcp-marshal-main.c: nm-dhcp-marshal.c nm-dhcp-marshal.h

