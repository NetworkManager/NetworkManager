INCLUDES = -I${top_srcdir}                       \
           -I${top_srcdir}/include               \
           -I${top_srcdir}/utils                 \
           -I${top_srcdir}/src                   \
           -I${top_srcdir}/src/named-manager

noinst_LTLIBRARIES = libdhcp-manager.la

libdhcp_manager_la_SOURCES =	nm-dhcp-manager.c	\
						nm-dhcp-manager.h

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
