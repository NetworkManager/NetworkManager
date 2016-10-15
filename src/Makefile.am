SUBDIRS = \
	settings/plugins \
	devices/adsl

if WITH_MODEM_MANAGER_1
SUBDIRS += devices/wwan	devices/bluetooth
endif

if WITH_WIFI
SUBDIRS += devices/wifi
endif

if WITH_TEAMDCTL
SUBDIRS += devices/team
endif

if ENABLE_TESTS
SUBDIRS += \
	dnsmasq-manager/tests \
	platform \
	devices \
	rdisc \
	supplicant-manager/tests \
	tests
endif
