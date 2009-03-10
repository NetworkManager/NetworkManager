EXTRA_DIST = \
	ifcfg-test-minimal \
	ifcfg-test-nm-controlled \
	ifcfg-test-wired-static \
	ifcfg-test-wired-dhcp \
	ifcfg-test-wired-global-gateway \
	network-test-wired-global-gateway \
	ifcfg-test-wired-never-default \
	network-test-wired-never-default \
	ifcfg-test-onboot-no \
	ifcfg-test-wifi-open \
	ifcfg-test-wifi-wep \
	keys-test-wifi-wep \
	ifcfg-test-wifi-wep-adhoc \
	keys-test-wifi-wep-adhoc \
	ifcfg-test-wifi-wpa-psk \
	keys-test-wifi-wpa-psk \
	ifcfg-test-wifi-wpa-psk-adhoc \
	keys-test-wifi-wpa-psk-adhoc \
	ifcfg-test-wifi-wpa-psk-hex \
	keys-test-wifi-wpa-psk-hex

check-local:
	@for f in $(EXTRA_DIST); do \
		chmod 0600 $(abs_srcdir)/$$f; \
	done

