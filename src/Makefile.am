
INCLUDES = 						\
	$(NM_CFLAGS) 			   		\
	$(OPENSSL_CFLAGS)				\
	-Wall						\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DG_DISABLE_DEPRECATED			\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

bin_PROGRAMS = NetworkManager

NetworkManager_SOURCES =					\
		NetworkManagerAP.c				\
		NetworkManagerAP.h				\
		NetworkManagerAPList.c			\
		NetworkManagerAPList.h			\
		NetworkManagerDbus.c			\
		NetworkManagerDbus.h			\
		NetworkManagerDevice.c			\
		NetworkManagerDevice.h			\
		NetworkManager.c				\
		NetworkManager.h				\
		NetworkManagerPolicy.c			\
		NetworkManagerPolicy.h			\
		NetworkManagerUtils.c			\
		NetworkManagerUtils.h			\
		NetworkManagerWireless.c			\
		NetworkManagerWireless.h			\
		backends/NetworkManagerSystem.h

EXTRA_NetworkManager_SOURCES =			\
		backends/NetworkManagerDebian.c \
		backends/NetworkManagerGentoo.c \
		backends/NetworkManagerRedHat.c


NetworkManager_LDADD = $(NM_LIBS) $(IWLIB) $(OPENSSL_LIBS) backends/$(SYSTEM_BACKEND_FILE)

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = NetworkManager.conf

helperdir = $(bindir)
helper_SCRIPTS = NMLoadModules

EXTRA_DIST = $(dbusservice_DATA) $(helper_SCRIPTS)
