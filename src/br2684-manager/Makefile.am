INCLUDES = \
	-I${top_srcdir} \
	-I${top_srcdir}/include \
	-I${top_srcdir}/libnm-util \
	-I${top_srcdir}/src \
	-I${top_srcdir}/src/logging \
	-I${top_builddir}/marshallers

noinst_LTLIBRARIES = libbr2684-manager.la

libbr2684_manager_la_SOURCES = \
	nm-br2684-manager.c \
	nm-br2684-manager.h

$(libbr2684_manager_la_OBJECTS): 
							   
libbr2684_manager_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLIBDIR=\"$(libdir)\"

libbr2684_manager_la_LIBADD = \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(GLIB_LIBS)
