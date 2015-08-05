libexec_PROGRAMS = nm-dhcp-helper

nm_dhcp_helper_SOURCES = nm-dhcp-helper.c

nm_dhcp_helper_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-core \
	-DG_LOG_DOMAIN=\""nm-dhcp-helper"\" \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DNMRUNDIR=\"$(nmrundir)\"

nm_dhcp_helper_LDADD = $(GLIB_LIBS)


# FIXME: remove when dbus-glib >= 0.100 or GDBus is required
dhcp_helper_conf = nm-dhcp-helper.conf

if !HAVE_DBUS_GLIB_100
dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = $(dhcp_helper_conf)
endif

EXTRA_DIST = $(dhcp_helper_conf)

