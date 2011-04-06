
if HAVE_SYSTEMD
systemdsystemunit_DATA = \
	NetworkManager.service \
	NetworkManager-wait-online.service

NetworkManager.service: NetworkManager.service.in
	$(edit) $< >$@

NetworkManager-wait-online.service: NetworkManager-wait-online.service.in
	$(edit) $< >$@

servicedir = $(datadir)/dbus-1/system-services
service_in_files = org.freedesktop.NetworkManager.service.in
service_DATA = $(service_in_files:.service.in=.service)

$(service_DATA): $(service_in_files) Makefile
	$(edit) $< >$@
endif

edit = sed \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@sbindir[@]|$(sbindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g'

EXTRA_DIST = \
	NetworkManager.service.in \
	NetworkManager-wait-online.service.in \
	org.freedesktop.NetworkManager.service.in

CLEANFILES = NetworkManager.service NetworkManager-wait-online.service org.freedesktop.NetworkManager.service
