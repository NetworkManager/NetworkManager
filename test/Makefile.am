INCLUDES = 					   \
	$(NM_CFLAGS) 			   \
	-DDBUS_API_SUBJECT_TO_CHANGE		   \
	-DBINDIR=\"$(bindir)\"			   \
	-DDATADIR=\"$(datadir)\"

noinst_PROGRAMS = nmclienttest

nmclienttest_SOURCES = nmclienttest.c

nmclienttest_LDADD = $(NM_LIBS)
