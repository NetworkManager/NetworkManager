INCLUDES = 						\
	$(NM_CFLAGS) 			   		\
	-Wall						\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DG_DISABLE_DEPRECATED			\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

bin_PROGRAMS = NMLaunchHelper

NMLaunchHelper_SOURCES = NMLaunchHelper.c

NMLaunchHelper_LDADD = $(NM_LIBS)

EXTRA_DIST = NetworkManager

initddir = $(sysconfdir)/rc.d/init.d
initd_SCRIPTS = NetworkManager
