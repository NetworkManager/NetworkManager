INCLUDES=-I$(srcdir)/../ \
	 -I$(top_srcdir)/libnm-glib \
	 -I$(top_srcdir)/libnm-util \
	 -I$(top_srcdir)/include \
	 -I$(top_srcdir)/src/settings
TESTS = check_ifnet
check_PROGRAMS = check_ifnet
check_ifnet_SOURCES = test_all.c 
check_ifnet_CPPFLAGS = $(CHECK_CFLAGS) $(GLIB_CFLAGS)
check_ifnet_LDADD = $(top_builddir)/libnm-util/libnm-util.la \
		    $(builddir)/../lib-ifnet-io.la \
		    $(CHECK_LIBS) \
		    $(GLIB_LIBS)
EXTRA_DIST = hostname \
			 net \
			 net.all \
			 nm-system-settings.conf \
			 wpa_supplicant.conf
