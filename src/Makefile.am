SUBDIRS =

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
