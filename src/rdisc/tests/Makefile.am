AM_CPPFLAGS = \
	-I${top_srcdir} \
	-I${top_srcdir}/src \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/libnm-util \
	-I${srcdir}/.. \
	$(GLIB_CFLAGS) \
	$(LIBNL_CFLAGS) \
	$(LIBNDP_CFLAGS)

AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS = $(GLIB_LIBS) $(CODE_COVERAGE_LDFLAGS)

@GNOME_CODE_COVERAGE_RULES@

noinst_PROGRAMS = \
	rdisc

rdisc_SOURCES = \
	rdisc.c \
	../nm-rdisc.c \
	../nm-fake-rdisc.c \
	../nm-lndp-rdisc.c \
	../../logging/nm-logging.c
rdisc_LDADD = $(LIBNDP_LIBS)
