INCLUDES=-I$(top_srcdir)/system-settings/plugins/ifnet\
	 -I$(top_srcdir)/libnm-glib \
	 -I$(top_srcdir)/libnm-util \
	 -I$(top_srcdir)/include \
	 -I$(top_srcdir)/src/system-settings
TESTS = check_ifnet
check_PROGRAMS = check_ifnet
check_ifnet_SOURCES = test_all.c 
check_ifnet_LDFLAGS = -g
check_ifnet_CPPFLAGS = $(CHECK_CFLAGS) $(GLIB_CFLAGS) -g
check_ifnet_LDADD = $(top_srcdir)/libnm-util/libnm-util.la\
		    $(top_srcdir)/system-settings/plugins/ifnet/lib-ifnet-io.la\
		    $(CHECK_LIBS)\
		    $(GLIB_LIBS)
