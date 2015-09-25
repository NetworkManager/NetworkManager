libexec_PROGRAMS = nm-dhcp-helper

nm_dhcp_helper_SOURCES = nm-dhcp-helper.c

nm_dhcp_helper_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/include \
	-I${top_builddir}/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DG_LOG_DOMAIN=\""nm-dhcp-helper"\" \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DNMRUNDIR=\"$(nmrundir)\"

nm_dhcp_helper_LDADD = $(GLIB_LIBS)
