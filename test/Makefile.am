INCLUDES =						\
	$(NM_CFLAGS)					\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

noinst_PROGRAMS = nmtest

nmtest_SOURCES = nmclienttest.c
nmtest_LDADD = $(NM_LIBS)
