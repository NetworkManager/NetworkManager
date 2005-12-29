INCLUDES = -I${top_srcdir}                    \
           -I${top_srcdir}/utils              \
           -I${top_srcdir}/include            \
           -I${top_srcdir}/libnm-util		\
		 -I${top_srcdir}/test

noinst_LTLIBRARIES=libtest-common.la


libtest_common_la_SOURCES= \
	test-common.c         \
	test-common.h

libtest_common_la_CPPFLAGS =			\
	$(GLIB_CFLAGS)					\
	-DG_DISABLE_DEPRECATED

libtest_common_la_LIBADD = $(GLIB_LIBS)

