INCLUDES = -I${top_srcdir}                    \
           -I${top_srcdir}/utils              \
           -I${top_srcdir}/include            \
           -I${top_srcdir}/libnm-util		\
		 -I${top_srcdir}/test

noinst_PROGRAMS = test-ciphers

test_ciphers_SOURCES = test-ciphers.c

test_ciphers_CPPFLAGS =		\
	$(DBUS_CFLAGS)					\
	$(GLIB_CFLAGS)					\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

test_ciphers_LDADD = \
          $(DBUS_LIBS)    \
          $(GLIB_LIBS)    \
		$(top_builddir)/libnm-util/libnm-util.la \
		$(top_builddir)/test/libtest-common.la
