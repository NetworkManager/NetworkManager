EXTRA_DIST = \
	ifcfg-test-minimal \
	ifcfg-test-nm-controlled \
	ifcfg-test-wired-static \
	ifcfg-test-wired-static-bootproto \
	ifcfg-test-wired-dhcp \
	ifcfg-test-wired-dhcp6-only \
	ifcfg-test-wired-global-gateway \
	network-test-wired-global-gateway \
	ifcfg-test-wired-never-default \
	network-test-wired-never-default \
	ifcfg-test-wired-defroute-no \
	ifcfg-test-wired-defroute-no-gatewaydev-yes \
	network-test-wired-defroute-no-gatewaydev-yes \
	ifcfg-test-wired-8021x-peap-mschapv2 \
	keys-test-wired-8021x-peap-mschapv2 \
	ifcfg-test-onboot-no \
	ifcfg-test-wifi-open \
	ifcfg-test-wifi-open-auto \
	ifcfg-test-wifi-open-ssid-quoted \
	ifcfg-test-wifi-open-ssid-long-quoted \
	ifcfg-test-wifi-open-ssid-hex \
	ifcfg-test-wifi-open-ssid-long-hex \
	ifcfg-test-wifi-open-ssid-bad-hex \
	ifcfg-test-wifi-wep \
	keys-test-wifi-wep \
	ifcfg-test-wifi-wep-adhoc \
	keys-test-wifi-wep-adhoc \
	ifcfg-test-wifi-wep-eap-ttls-chap \
	keys-test-wifi-wep-eap-ttls-chap \
	ifcfg-test-wifi-leap \
	keys-test-wifi-leap \
	ifcfg-test-wifi-wpa-psk \
	keys-test-wifi-wpa-psk \
	ifcfg-test-wifi-wpa-psk-unquoted \
	keys-test-wifi-wpa-psk-unquoted \
	ifcfg-test-wifi-wpa-psk-unquoted2 \
	keys-test-wifi-wpa-psk-unquoted2 \
	ifcfg-test-wifi-wpa-psk-adhoc \
	keys-test-wifi-wpa-psk-adhoc \
	ifcfg-test-wifi-wpa-psk-hex \
	keys-test-wifi-wpa-psk-hex \
	ifcfg-test-wifi-wpa-eap-tls \
	keys-test-wifi-wpa-eap-tls \
	ifcfg-test-wifi-wpa-eap-ttls-tls \
	keys-test-wifi-wpa-eap-ttls-tls \
	test_ca_cert.pem \
	test1_key_and_cert.pem \
	ifcfg-test-ibft-dhcp \
	ifcfg-test-ibft-static \
	ifcfg-test-static-routes-legacy \
	route-test-static-routes-legacy \
	ifcfg-test-wired-static-routes \
	route-test-wired-static-routes \
	ifcfg-test-wired-static-routes-legacy \
	route-test-wired-static-routes-legacy \
	ifcfg-test-wired-ipv6-manual \
	route6-test-wired-ipv6-manual \
	ifcfg-test-wired-static-no-prefix-8 \
	ifcfg-test-wired-static-no-prefix-16 \
	ifcfg-test-wired-static-no-prefix-24 \
	ifcfg-test-wired-ipv6-only \
	ifcfg-test-wifi-wep-passphrase \
	keys-test-wifi-wep-passphrase \
	ifcfg-test-wifi-wep-40-ascii \
	keys-test-wifi-wep-40-ascii \
	ifcfg-test-wifi-wep-104-ascii \
	keys-test-wifi-wep-104-ascii \
	ifcfg-test-wired-qeth-static \
	ifcfg-test-bridge-main \
	ifcfg-test-bridge-component \
	ifcfg-test-vlan-interface

check-local:
	@for f in $(EXTRA_DIST); do \
		chmod 0600 $(abs_srcdir)/$$f; \
	done

# Make the special temp dir for some written connections
	mkdir -p $(abs_builddir)/tmp

