if BUILD_NMTUI

SUBDIRS = newt .

AM_CPPFLAGS= \
	-I$(top_srcdir) \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/libnm \
	-I$(top_builddir)/libnm \
	-I$(srcdir)/newt \
	-I$(top_srcdir)/clients/common \
	$(GLIB_CFLAGS) \
	$(NEWT_CFLAGS) \
	$(GUDEV_CFLAGS) \
	-DG_LOG_DOMAIN=\""nmtui"\" \
	-DLOCALEDIR=\""$(localedir)"\" \
	$(NULL)

bin_PROGRAMS = nmtui
links = nmtui-edit nmtui-connect nmtui-hostname

install-exec-hook:
	for link in $(links); do \
		$(LN_S) -f nmtui "$(DESTDIR)$(bindir)/$$link"; \
	done

uninstall-hook:
	for link in $(links); do \
		rm -f "$(DESTDIR)$(bindir)/$$link"; \
	done

nmtui_SOURCES = \
	nmtui.c \
	nmtui.h \
	nmtui-connect.c \
	nmtui-connect.h \
	nmtui-edit.c \
	nmtui-edit.h \
	nmtui-hostname.c \
	nmtui-hostname.h \
	\
	nm-editor-bindings.c \
	nm-editor-bindings.h \
	nm-editor-utils.c \
	nm-editor-utils.h \
	\
	nmt-address-list.c \
	nmt-address-list.h \
	nmt-connect-connection-list.c \
	nmt-connect-connection-list.h \
	nmt-device-entry.c \
	nmt-device-entry.h \
	nmt-edit-connection-list.c \
	nmt-edit-connection-list.h \
	nmt-editor-grid.c \
	nmt-editor-grid.h \
	nmt-editor-page.c \
	nmt-editor-page.h \
	nmt-editor-page-device.c \
	nmt-editor-page-device.h \
	nmt-editor-section.c \
	nmt-editor-section.h \
	nmt-editor.c \
	nmt-editor.h \
	nmt-ip-entry.c \
	nmt-ip-entry.h \
	nmt-mac-entry.c \
	nmt-mac-entry.h \
	nmt-mtu-entry.c \
	nmt-mtu-entry.h \
	nmt-page-bond.c \
	nmt-page-bond.h \
	nmt-page-bridge.c \
	nmt-page-bridge.h \
	nmt-page-bridge-port.c \
	nmt-page-bridge-port.h \
	nmt-page-dsl.c \
	nmt-page-dsl.h \
	nmt-page-ethernet.c \
	nmt-page-ethernet.h \
	nmt-page-infiniband.c \
	nmt-page-infiniband.h \
	nmt-page-ip4.c \
	nmt-page-ip4.h \
	nmt-page-ip6.c \
	nmt-page-ip6.h \
	nmt-page-ppp.c \
	nmt-page-ppp.h \
	nmt-page-team.c \
	nmt-page-team.h \
	nmt-page-team-port.c \
	nmt-page-team-port.h \
	nmt-page-vlan.c \
	nmt-page-vlan.h \
	nmt-page-wifi.c \
	nmt-page-wifi.h \
	nmt-password-dialog.c \
	nmt-password-dialog.h \
	nmt-password-fields.c \
	nmt-password-fields.h \
	nmt-route-editor.c \
	nmt-route-editor.h \
	nmt-route-entry.c \
	nmt-route-entry.h \
	nmt-route-table.c \
	nmt-route-table.h \
	nmt-slave-list.c \
	nmt-slave-list.h \
	nmt-utils.c \
	nmt-utils.h \
	nmt-widget-list.c \
	nmt-widget-list.h \
	$(srcdir)/../common/nm-secret-agent-simple.c \
	$(srcdir)/../common/nm-secret-agent-simple.h \
	$(srcdir)/../common/nm-vpn-helpers.c \
	$(srcdir)/../common/nm-vpn-helpers.h \
	$(NULL)

nmtui_LDADD = \
	$(top_builddir)/libnm/libnm.la \
	$(builddir)/newt/libnmt-newt.a \
	$(GUDEV_LIBS) \
	$(NEWT_LIBS) \
	$(GLIB_LIBS) \
	$(NULL)

endif
