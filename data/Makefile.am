
if HAVE_SYSTEMD
systemdsystemunit_DATA = \
	NetworkManager.service \
	NetworkManager-wait-online.service \
	NetworkManager-dispatcher.service

NetworkManager.service: NetworkManager.service.in
	$(edit) $< >$@

if HAVE_SYSTEMD_200
NetworkManager-wait-online.service: NetworkManager-wait-online.service.in
	$(edit) $< >$@
else
NetworkManager-wait-online.service: NetworkManager-wait-online-systemd-pre200.service.in
	$(edit) $< >$@
endif

NetworkManager-dispatcher.service: NetworkManager-dispatcher.service.in
	$(edit) $< >$@

servicedir = $(datadir)/dbus-1/system-services
service_in_files = org.freedesktop.NetworkManager.service.in
service_DATA = $(service_in_files:.service.in=.service)

$(service_DATA): $(service_in_files) Makefile
	$(edit) $< >$@

install-exec-local:
	install -d $(DESTDIR)$(systemdsystemunitdir)/network-online.target.wants
	ln -sf $(systemdsystemunitdir)/NetworkManager-wait-online.service $(DESTDIR)$(systemdsystemunitdir)/network-online.target.wants
endif

examplesdir = $(docdir)/examples
examples_DATA = server.conf

if WITH_UDEV_DIR
udevrulesdir = $(UDEV_DIR)/rules.d
udevrules_DATA = \
	85-nm-unmanaged.rules
endif

server.conf: server.conf.in
	$(edit) $< >$@

edit = sed \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@sbindir[@]|$(sbindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g' \
	-e 's|@libexecdir[@]|$(libexecdir)|g' \
	-e 's|@DISTRO_NETWORK_SERVICE[@]|$(DISTRO_NETWORK_SERVICE)|g'

EXTRA_DIST = \
	NetworkManager.service.in \
	NetworkManager-wait-online.service.in \
	NetworkManager-wait-online-systemd-pre200.service.in \
	NetworkManager-dispatcher.service.in \
	org.freedesktop.NetworkManager.service.in \
	85-nm-unmanaged.rules \
	server.conf.in

CLEANFILES = \
	NetworkManager.service \
	NetworkManager-wait-online.service \
	NetworkManager-dispatcher.service \
	org.freedesktop.NetworkManager.service \
	server.conf

