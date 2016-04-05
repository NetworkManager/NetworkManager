libexec_PROGRAMS = nm-dhcp-helper

nm_dhcp_helper_SOURCES = nm-dhcp-helper.c

nm_dhcp_helper_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/shared \
	-I${top_builddir}/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DG_LOG_DOMAIN=\""nm-dhcp-helper"\" \
	-DNMRUNDIR=\"$(nmrundir)\"

nm_dhcp_helper_LDADD = $(GLIB_LIBS)
