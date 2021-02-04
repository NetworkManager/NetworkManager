include $(GLIB_MAKEFILE)
-include $(INTROSPECTION_MAKEFILE)
include Makefile.vapigen

@GNOME_CODE_COVERAGE_RULES@

@NM_LOG_COMPILER@

###############################################################################

AUTOMAKE_OPTIONS = subdir-objects

noinst_LTLIBRARIES =
check_LTLIBRARIES =
noinst_PROGRAMS =
noinst_LIBRARIES =
check_PROGRAMS =
noinst_DATA =
sbin_PROGRAMS =
bin_PROGRAMS =
libexec_PROGRAMS =
dist_libexec_SCRIPTS =
lib_LTLIBRARIES =
plugin_LTLIBRARIES =
core_plugins =
service_DATA =
man_MANS =
examples_DATA =
CLEANFILES =
DISTCLEANFILES =
EXTRA_DIST =
EXTRA_LTLIBRARIES =
dist_hook =
dist_dependencies =
dist_configure_check =
install_data_hook =
install_exec_hook =
uninstall_hook =
TESTS =
BUILT_SOURCES =
GLIB_GENERATED =
man_pages =
man_pages_autogen =
check_programs =
check_programs_norun =
check_ltlibraries =
check_local =
VAPIGEN_VAPIS =
dbusservice_DATA =
dbusactivation_DATA =
systemdsystemunit_DATA =

INTROSPECTION_GIRS =
INTROSPECTION_SCANNER_ARGS =
INTROSPECTION_COMPILER_ARGS =
# Pass SANITIZER_ENV where a command that uses built libraries is
# executed, to suppress possible errors
INTROSPECTION_SCANNER_ENV = $(SANITIZER_ENV) LDFLAGS="$(SANITIZER_LIB_LDFLAGS)"

libnmincludedir = $(includedir)/libnm
libnminclude_HEADERS =
nodist_libnminclude_HEADERS =

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA =

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES =

vapidir = $(datadir)/vala/vapi
vapi_DATA =

examplesdir = $(docdir)/examples

rundir=$(runstatedir)/NetworkManager
statedir=$(localstatedir)/lib/NetworkManager

plugindir=$(pkglibdir)/$(NM_DIST_VERSION)

dbusactivationdir = $(datadir)/dbus-1/system-services

servicedir = $(datadir)/dbus-1/system-services

completiondir = $(datadir)/bash-completion/completions

nmlocaledir = $(datadir)/locale

INTROSPECTION_EXTRA_CFLAGS = -Wno-incompatible-pointer-types-discards-qualifiers

GLIB_MKENUMS_H_FLAGS = --identifier-prefix NM
GLIB_MKENUMS_C_FLAGS = --identifier-prefix NM

SUBDIRS = \
	. \
	po

if HAVE_DOCS

SUBDIRS += \
	docs/libnm \
	docs/api

endif

dflt_cppflags = -std=gnu11

###############################################################################

include config-extra.h.mk

DISTCLEANFILES += config-extra.h

$(libnm_core_lib_h_pub_mkenums):     config-extra.h
libnm-core/.dirstamp:                config-extra.h
shared/.dirstamp:                    config-extra.h
shared/nm-base/.dirstamp:            config-extra.h
shared/nm-glib-aux/.dirstamp:        config-extra.h
shared/nm-glib-aux/tests/.dirstamp:  config-extra.h
shared/nm-platform/.dirstamp:        config-extra.h
shared/nm-platform/tests/.dirstamp:  config-extra.h
shared/nm-std-aux/.dirstamp:         config-extra.h
shared/nm-udev-aux/.dirstamp:        config-extra.h
shared/systemd/.dirstamp:            config-extra.h
shared/systemd/src/basic/.dirstamp:  config-extra.h
shared/systemd/src/shared/.dirstamp: config-extra.h
src/core/dhcp/.dirstamp:             config-extra.h

###############################################################################

set_sanitizer_env = \
	[ -n "$(SANITIZER_ENV)" ] && export $(SANITIZER_ENV) ; \
	if echo $(SANITIZER_LIB_CFLAGS) $(SANITIZER_EXEC_CFLAGS) | grep -e -fsanitize=address > /dev/null; then \
		[ -n "$(1)" ] && export LD_PRELOAD="$${LD_PRELOAD}:$$(ldd $(1) | grep libasan\.so\.. -o | head -n 1)"; \
		[ -n "$(2)" ] && export LD_PRELOAD="$${LD_PRELOAD}:$$(ldd $(2) | grep libasan\.so\.. -o | head -n 1)"; \
	fi

check_so_symbols = \
	$(call set_sanitizer_env,$(1),$(builddir)/src/core/NetworkManager); \
	LD_BIND_NOW=1 LD_PRELOAD=$${LD_PRELOAD}:$(1) $(builddir)/src/core/NetworkManager --version >/dev/null

###############################################################################

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-tests=yes \
	--with-valgrind=no \
	--enable-gtk-doc \
	--enable-more-warnings=error \
	--with-udev-dir=$$dc_install_base/lib/udev \
	--with-wext=no \
	--enable-ifcfg-rh \
	--enable-ifupdown \
	--disable-dependency-tracking \
	$(NULL)

dist-configure-check:
	@echo "*** 'make dist' requires '--enable-gtk-doc --enable-introspection'. ***"
	@false
if !BUILD_DOCS
dist_configure_check += dist-configure-check
endif

dist: $(dist_configure_check) $(dist_dependencies)

DISTCLEANFILES += intltool-extract intltool-merge intltool-update

###############################################################################

install-data-hook-dirs:
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(nmconfdir)/conf.d
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(nmconfdir)/system-connections
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(nmconfdir)/dnsmasq.d
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(nmconfdir)/dnsmasq-shared.d
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(nmlibdir)/conf.d
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(nmlibdir)/VPN
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(nmlibdir)/system-connections
	$(mkinstalldirs) -m 0700 $(DESTDIR)$(nmstatedir)
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(plugindir)

install_data_hook += install-data-hook-dirs

###############################################################################

data_edit = sed \
	-e 's|@NM_VERSION[@]|$(NM_VERSION)|g' \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@sbindir[@]|$(sbindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@nmrundir[@]|$(nmrundir)|g' \
	-e 's|@nmstatedir[@]|$(nmstatedir)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g' \
	-e 's|@libexecdir[@]|$(libexecdir)|g' \
	-e 's|@DISTRO_NETWORK_SERVICE[@]|$(DISTRO_NETWORK_SERVICE)|g' \
	-e 's|@NM_CONFIG_DEFAULT_MAIN_AUTH_POLKIT_TEXT[@]|$(NM_CONFIG_DEFAULT_MAIN_AUTH_POLKIT_TEXT)|g' \
	-e 's|@NM_CONFIG_DEFAULT_LOGGING_BACKEND_TEXT[@]|$(NM_CONFIG_DEFAULT_LOGGING_BACKEND_TEXT)|g' \
	-e 's|@NM_CONFIG_DEFAULT_LOGGING_AUDIT_TEXT[@]|$(NM_CONFIG_DEFAULT_LOGGING_AUDIT_TEXT)|g' \
	-e 's|@NM_CONFIG_DEFAULT_MAIN_RC_MANAGER[@]|$(NM_CONFIG_DEFAULT_MAIN_RC_MANAGER)|g' \
	-e 's|@NM_CONFIG_DEFAULT_MAIN_DHCP[@]|$(NM_CONFIG_DEFAULT_MAIN_DHCP)|g'

###############################################################################

polkit_policydir = $(datadir)/polkit-1/actions

dist_polkit_policy_in_in_files = \
	data/org.freedesktop.NetworkManager.policy.in.in

polkit_policy_DATA = $(dist_polkit_policy_in_in_files:.policy.in.in=.policy)

@INTLTOOL_POLICY_RULE@

DISTCLEANFILES += $(polkit_policy_DATA)

###############################################################################

EXTRA_DIST += \
	shared/c-stdaux/src/c-stdaux.h \
	$(NULL)

###############################################################################

noinst_LTLIBRARIES += shared/libcsiphash.la

shared_libcsiphash_la_CFLAGS = \
	$(AM_CFLAGS) \
	-std=c11 \
	-I$(srcdir)/shared/c-stdaux/src \
	$(NULL)

shared_libcsiphash_la_CPPFLAGS = \
	$(CODE_COVERAGE_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

shared_libcsiphash_la_LDFLAGS = \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

shared_libcsiphash_la_SOURCES = \
	shared/c-siphash/src/c-siphash.c \
	shared/c-siphash/src/c-siphash.h \
	$(NULL)

###############################################################################

noinst_LTLIBRARIES += shared/libcrbtree.la

shared_libcrbtree_la_CFLAGS = \
	$(AM_CFLAGS) \
	-std=c11 \
	-I$(srcdir)/shared/c-stdaux/src \
	$(NULL)

shared_libcrbtree_la_CPPFLAGS = \
	$(CODE_COVERAGE_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

shared_libcrbtree_la_LDFLAGS = \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

shared_libcrbtree_la_SOURCES = \
	shared/c-rbtree/src/c-rbtree.c \
	shared/c-rbtree/src/c-rbtree.h \
	shared/c-rbtree/src/c-rbtree-private.h \
	$(NULL)

###############################################################################

noinst_LTLIBRARIES += shared/libnacd.la

shared_libnacd_la_CFLAGS = \
	$(AM_CFLAGS) \
	-std=c11 \
	-Wno-pointer-arith \
	-Wno-vla \
	$(NULL)

shared_libnacd_la_CPPFLAGS = \
	-D_GNU_SOURCE \
	-DSO_ATTACH_BPF=50 \
	$(CODE_COVERAGE_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	-I$(srcdir)/shared/c-stdaux/src \
	-I$(srcdir)/shared/c-list/src \
	-I$(srcdir)/shared/c-siphash/src \
	-I$(srcdir)/shared/c-rbtree/src \
	$(NULL)

shared_libnacd_la_LDFLAGS = \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

shared_libnacd_la_SOURCES = \
	shared/n-acd/src/n-acd.c \
	shared/n-acd/src/n-acd.h \
	shared/n-acd/src/n-acd-private.h \
	shared/n-acd/src/n-acd-probe.c \
	shared/n-acd/src/util/timer.c \
	shared/n-acd/src/util/timer.h \
	$(NULL)

if WITH_EBPF
shared_libnacd_la_SOURCES += shared/n-acd/src/n-acd-bpf.c
else
shared_libnacd_la_SOURCES += shared/n-acd/src/n-acd-bpf-fallback.c
endif

###############################################################################

noinst_LTLIBRARIES += shared/libndhcp4.la

shared_libndhcp4_la_CFLAGS = \
	$(AM_CFLAGS) \
	-std=c11 \
	-Wno-error=declaration-after-statement \
	-Wno-pointer-arith \
	$(NULL)

shared_libndhcp4_la_CPPFLAGS = \
	-D_GNU_SOURCE \
	$(CODE_COVERAGE_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	-I$(srcdir)/shared/c-stdaux/src \
	-I$(srcdir)/shared/c-list/src \
	-I$(srcdir)/shared/c-siphash/src \
	$(NULL)

shared_libndhcp4_la_LDFLAGS = \
	$(SANITIZER_LIB_LDFLAGS)

shared_libndhcp4_la_SOURCES = \
	shared/n-dhcp4/src/n-dhcp4-c-connection.c \
	shared/n-dhcp4/src/n-dhcp4-c-lease.c \
	shared/n-dhcp4/src/n-dhcp4-c-probe.c \
	shared/n-dhcp4/src/n-dhcp4-client.c \
	shared/n-dhcp4/src/n-dhcp4-incoming.c \
	shared/n-dhcp4/src/n-dhcp4-outgoing.c \
	shared/n-dhcp4/src/n-dhcp4-private.h \
	shared/n-dhcp4/src/n-dhcp4-socket.c \
	shared/n-dhcp4/src/n-dhcp4.h \
	shared/n-dhcp4/src/util/packet.c \
	shared/n-dhcp4/src/util/packet.h \
	shared/n-dhcp4/src/util/socket.c \
	shared/n-dhcp4/src/util/socket.h \
	$(NULL)

###############################################################################

noinst_LTLIBRARIES += shared/nm-std-aux/libnm-std-aux.la

shared_nm_std_aux_libnm_std_aux_la_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	$(CODE_COVERAGE_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	-DG_LOG_DOMAIN=\""libnm"\" \
	-DNETWORKMANAGER_COMPILATION='0' \
	$(NULL)

shared_nm_std_aux_libnm_std_aux_la_SOURCES = \
	shared/c-list/src/c-list.h \
	shared/nm-std-aux/c-list-util.c \
	shared/nm-std-aux/c-list-util.h \
	shared/nm-std-aux/nm-dbus-compat.h \
	shared/nm-std-aux/nm-std-aux.h \
	shared/nm-std-aux/nm-std-utils.c \
	shared/nm-std-aux/nm-std-utils.h \
	shared/nm-std-aux/unaligned.h \
	$(NULL)

shared_nm_std_aux_libnm_std_aux_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

###############################################################################

shared_nm_glib_aux_cppflags = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	$(CODE_COVERAGE_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DG_LOG_DOMAIN=\""libnm"\" \
	-DNETWORKMANAGER_COMPILATION='(NM_NETWORKMANAGER_COMPILATION_GLIB|NM_NETWORKMANAGER_COMPILATION_WITH_GLIB_I18N_LIB)' \
	$(NULL)

noinst_LTLIBRARIES += shared/nm-glib-aux/libnm-glib-aux.la

shared_nm_glib_aux_libnm_glib_aux_la_CPPFLAGS = \
	$(shared_nm_glib_aux_cppflags) \
	$(NULL)

shared_nm_glib_aux_libnm_glib_aux_la_SOURCES = \
	shared/nm-glib-aux/nm-c-list.h \
	shared/nm-glib-aux/nm-dbus-aux.c \
	shared/nm-glib-aux/nm-dbus-aux.h \
	shared/nm-glib-aux/nm-dedup-multi.c \
	shared/nm-glib-aux/nm-dedup-multi.h \
	shared/nm-glib-aux/nm-enum-utils.c \
	shared/nm-glib-aux/nm-enum-utils.h \
	shared/nm-glib-aux/nm-errno.c \
	shared/nm-glib-aux/nm-errno.h \
	shared/nm-glib-aux/nm-glib.h \
	shared/nm-glib-aux/nm-hash-utils.c \
	shared/nm-glib-aux/nm-hash-utils.h \
	shared/nm-glib-aux/nm-io-utils.c \
	shared/nm-glib-aux/nm-io-utils.h \
	shared/nm-glib-aux/nm-jansson.h \
	shared/nm-glib-aux/nm-json-aux.c \
	shared/nm-glib-aux/nm-json-aux.h \
	shared/nm-glib-aux/nm-keyfile-aux.c \
	shared/nm-glib-aux/nm-keyfile-aux.h \
	shared/nm-glib-aux/nm-logging-base.c \
	shared/nm-glib-aux/nm-logging-base.h \
	shared/nm-glib-aux/nm-logging-fwd.h \
	shared/nm-glib-aux/nm-macros-internal.h \
	shared/nm-glib-aux/nm-obj.h \
	shared/nm-glib-aux/nm-random-utils.c \
	shared/nm-glib-aux/nm-random-utils.h \
	shared/nm-glib-aux/nm-ref-string.c \
	shared/nm-glib-aux/nm-ref-string.h \
	shared/nm-glib-aux/nm-secret-utils.c \
	shared/nm-glib-aux/nm-secret-utils.h \
	shared/nm-glib-aux/nm-shared-utils.c \
	shared/nm-glib-aux/nm-shared-utils.h \
	shared/nm-glib-aux/nm-str-buf.h \
	shared/nm-glib-aux/nm-time-utils.c \
	shared/nm-glib-aux/nm-time-utils.h \
	shared/nm-glib-aux/nm-value-type.h \
	$(NULL)

shared_nm_glib_aux_libnm_glib_aux_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

shared_nm_glib_aux_libnm_glib_aux_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

###############################################################################

noinst_LTLIBRARIES += shared/nm-udev-aux/libnm-udev-aux.la

shared_nm_udev_aux_libnm_udev_aux_la_CPPFLAGS = \
	$(shared_nm_glib_aux_cppflags) \
	$(LIBUDEV_CFLAGS) \
	$(NULL)

shared_nm_udev_aux_libnm_udev_aux_la_SOURCES = \
	shared/nm-udev-aux/nm-udev-utils.c \
	shared/nm-udev-aux/nm-udev-utils.h \
	$(NULL)

shared_nm_udev_aux_libnm_udev_aux_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

shared_nm_udev_aux_libnm_udev_aux_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBUDEV_LIBS) \
	$(NULL)

###############################################################################

noinst_LTLIBRARIES += shared/nm-base/libnm-base.la

shared_nm_base_libnm_base_la_CPPFLAGS = \
	$(shared_nm_glib_aux_cppflags) \
	$(NULL)

shared_nm_base_libnm_base_la_SOURCES = \
	shared/nm-base/nm-base.h \
	shared/nm-base/nm-ethtool-base.c \
	shared/nm-base/nm-ethtool-base.h \
	shared/nm-base/nm-ethtool-utils-base.h \
	$(NULL)

shared_nm_base_libnm_base_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

shared_nm_base_libnm_base_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

###############################################################################

noinst_LTLIBRARIES += shared/nm-log-core/libnm-log-core.la

shared_nm_log_core_libnm_log_core_la_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	$(CODE_COVERAGE_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SYSTEMD_JOURNAL_CFLAGS) \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION='(NM_NETWORKMANAGER_COMPILATION_GLIB|NM_NETWORKMANAGER_COMPILATION_WITH_GLIB_I18N_LIB)' \
	$(NULL)

shared_nm_log_core_libnm_log_core_la_SOURCES = \
	shared/nm-log-core/nm-logging.c \
	shared/nm-log-core/nm-logging.h \
	$(NULL)

shared_nm_log_core_libnm_log_core_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

shared_nm_log_core_libnm_log_core_la_LIBADD = \
	$(GLIB_LIBS) \
	$(SYSTEMD_JOURNAL_LIBS) \
	$(NULL)

###############################################################################

noinst_LTLIBRARIES += shared/nm-platform/libnm-platform.la

shared_nm_platform_libnm_platform_la_CPPFLAGS = \
	$(shared_nm_glib_aux_cppflags) \
	$(NULL)

shared_nm_platform_libnm_platform_la_SOURCES = \
	shared/nm-platform/nm-netlink.c \
	shared/nm-platform/nm-netlink.h \
	shared/nm-platform/nm-platform-utils.c \
	shared/nm-platform/nm-platform-utils.h \
	shared/nm-platform/nmp-base.h \
	shared/nm-platform/nmp-netns.c \
	shared/nm-platform/nmp-netns.h \
	$(NULL)

shared_nm_platform_libnm_platform_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

shared_nm_platform_libnm_platform_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

###############################################################################

check_programs += shared/nm-platform/tests/test-nm-platform

shared_nm_platform_tests_test_nm_platform_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	-DNETWORKMANAGER_COMPILATION_TEST \
	-DNETWORKMANAGER_COMPILATION='(NM_NETWORKMANAGER_COMPILATION_GLIB|NM_NETWORKMANAGER_COMPILATION_WITH_GLIB_I18N_PROG)' \
	$(CODE_COVERAGE_CFLAGS) \
	$(SYSTEMD_JOURNAL_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

shared_nm_platform_tests_test_nm_platform_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

shared_nm_platform_tests_test_nm_platform_LDADD = \
	shared/nm-platform/libnm-platform.la \
	shared/nm-log-core/libnm-log-core.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	$(SYSTEMD_JOURNAL_LIBS) \
	$(GLIB_LIBS) \
	$(NULL)

EXTRA_DIST += \
	shared/nm-platform/tests/meson.build \
	$(NULL)

###############################################################################

noinst_LTLIBRARIES += libnm-core/nm-libnm-core-intern/libnm-libnm-core-intern.la

libnm_core_nm_libnm_core_intern_libnm_libnm_core_intern_la_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	-I$(builddir)/shared \
	-I$(srcdir)/libnm-core \
	-I$(builddir)/libnm-core \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	-DG_LOG_DOMAIN=\""libnm"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIBNM_CORE \
	$(NULL)

libnm_core_nm_libnm_core_intern_libnm_libnm_core_intern_la_SOURCES = \
	libnm-core/nm-libnm-core-intern/nm-auth-subject.c \
	libnm-core/nm-libnm-core-intern/nm-auth-subject.h \
	libnm-core/nm-libnm-core-intern/nm-common-macros.h \
	libnm-core/nm-libnm-core-intern/nm-libnm-core-utils.c \
	libnm-core/nm-libnm-core-intern/nm-libnm-core-utils.h \
	$(NULL)

libnm_core_nm_libnm_core_intern_libnm_libnm_core_intern_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

libnm_core_nm_libnm_core_intern_libnm_libnm_core_intern_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

$(libnm_core_nm_libnm_core_intern_libnm_libnm_core_intern_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

EXTRA_DIST += libnm-core/nm-libnm-core-intern/README.md

###############################################################################

noinst_LTLIBRARIES += libnm-core/nm-libnm-core-aux/libnm-libnm-core-aux.la

libnm_core_nm_libnm_core_aux_libnm_libnm_core_aux_la_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	-I$(builddir)/shared \
	-I$(srcdir)/libnm-core \
	-I$(builddir)/libnm-core \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	-DG_LOG_DOMAIN=\""libnm"\" \
	-DNETWORKMANAGER_COMPILATION='(NM_NETWORKMANAGER_COMPILATION_WITH_GLIB|NM_NETWORKMANAGER_COMPILATION_WITH_GLIB_I18N_LIB)' \
	$(NULL)

libnm_core_nm_libnm_core_aux_libnm_libnm_core_aux_la_SOURCES = \
	libnm-core/nm-libnm-core-aux/nm-dispatcher-api.h \
	libnm-core/nm-libnm-core-aux/nm-libnm-core-aux.c \
	libnm-core/nm-libnm-core-aux/nm-libnm-core-aux.h \
	$(NULL)

libnm_core_nm_libnm_core_aux_libnm_libnm_core_aux_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

libnm_core_nm_libnm_core_aux_libnm_libnm_core_aux_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

$(libnm_core_nm_libnm_core_aux_libnm_libnm_core_aux_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

EXTRA_DIST += libnm-core/nm-libnm-core-aux/README.md

###############################################################################

noinst_LTLIBRARIES += libnm-core/nm-keyfile/libnm-keyfile.la

libnm_core_nm_keyfile_libnm_keyfile_la_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	-I$(builddir)/shared \
	-I$(srcdir)/libnm-core \
	-I$(builddir)/libnm-core \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	-DG_LOG_DOMAIN=\""libnm"\" \
	-DNETWORKMANAGER_COMPILATION='(NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_CORE_INTERNAL|NM_NETWORKMANAGER_COMPILATION_WITH_GLIB|NM_NETWORKMANAGER_COMPILATION_WITH_GLIB_I18N_LIB)' \
	$(NULL)

libnm_core_nm_keyfile_libnm_keyfile_la_SOURCES = \
	libnm-core/nm-keyfile/nm-keyfile-internal.h \
	libnm-core/nm-keyfile/nm-keyfile-utils.c \
	libnm-core/nm-keyfile/nm-keyfile-utils.h \
	libnm-core/nm-keyfile/nm-keyfile.c \
	$(NULL)

libnm_core_nm_keyfile_libnm_keyfile_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

libnm_core_nm_keyfile_libnm_keyfile_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

$(libnm_core_nm_keyfile_libnm_keyfile_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

###############################################################################

noinst_LTLIBRARIES += libnm/nm-libnm-aux/libnm-libnm-aux.la

libnm_nm_libnm_aux_libnm_libnm_aux_la_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	-I$(builddir)/shared \
	-I$(srcdir)/libnm-core \
	-I$(builddir)/libnm-core \
	-I$(srcdir)/libnm \
	-I$(builddir)/libnm \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	-DG_LOG_DOMAIN=\""libnmc"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT \
	$(NULL)

libnm_nm_libnm_aux_libnm_libnm_aux_la_SOURCES = \
	libnm/nm-libnm-aux/nm-libnm-aux.c \
	libnm/nm-libnm-aux/nm-libnm-aux.h \
	$(NULL)

libnm_nm_libnm_aux_libnm_libnm_aux_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

libnm_nm_libnm_aux_libnm_libnm_aux_la_LIBADD = \
	$(GLIB_LIBS) \
	libnm/libnm.la \
	$(NULL)

$(libnm_nm_libnm_aux_libnm_libnm_aux_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(libnm_nm_libnm_aux_libnm_libnm_aux_la_OBJECTS): $(libnm_lib_h_pub_mkenums)

EXTRA_DIST += libnm/nm-libnm-aux/README.md

###############################################################################

EXTRA_DIST += \
	shared/nm-glib-aux/tests/meson.build \
	shared/README.md \
	$(NULL)

###############################################################################

check_programs += shared/nm-glib-aux/tests/test-shared-general

shared_nm_glib_aux_tests_test_shared_general_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	-DNETWORKMANAGER_COMPILATION_TEST \
	-DNETWORKMANAGER_COMPILATION='(NM_NETWORKMANAGER_COMPILATION_GLIB|NM_NETWORKMANAGER_COMPILATION_WITH_GLIB_I18N_PROG)' \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

shared_nm_glib_aux_tests_test_shared_general_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

shared_nm_glib_aux_tests_test_shared_general_LDADD = \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/systemd/libnm-systemd-logging-stub.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	$(GLIB_LIBS) \
	$(NULL)

###############################################################################

if WITH_JANSSON

check_programs += shared/nm-glib-aux/tests/test-json-aux

shared_nm_glib_aux_tests_test_json_aux_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	-DNETWORKMANAGER_COMPILATION_TEST \
	-DNETWORKMANAGER_COMPILATION='(NM_NETWORKMANAGER_COMPILATION_GLIB|NM_NETWORKMANAGER_COMPILATION_WITH_GLIB_I18N_PROG)' \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(JANSSON_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

shared_nm_glib_aux_tests_test_json_aux_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

shared_nm_glib_aux_tests_test_json_aux_LDADD = \
	$(JANSSON_LIBS) \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/systemd/libnm-systemd-logging-stub.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	$(GLIB_LIBS) \
	$(NULL)

endif

###############################################################################

noinst_LTLIBRARIES += introspection/libnmdbus.la

introspection_libnmdbus_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(INTROSPECTION_EXTRA_CFLAGS) \
	$(NULL)

introspection_sources = \
	introspection/org.freedesktop.NetworkManager.AccessPoint.c \
	introspection/org.freedesktop.NetworkManager.AccessPoint.h \
	introspection/org.freedesktop.NetworkManager.AgentManager.c \
	introspection/org.freedesktop.NetworkManager.AgentManager.h \
	introspection/org.freedesktop.NetworkManager.Checkpoint.c \
	introspection/org.freedesktop.NetworkManager.Checkpoint.h \
	introspection/org.freedesktop.NetworkManager.Connection.Active.c \
	introspection/org.freedesktop.NetworkManager.Connection.Active.h \
	introspection/org.freedesktop.NetworkManager.DHCP4Config.c \
	introspection/org.freedesktop.NetworkManager.DHCP4Config.h \
	introspection/org.freedesktop.NetworkManager.DHCP6Config.c \
	introspection/org.freedesktop.NetworkManager.DHCP6Config.h \
	introspection/org.freedesktop.NetworkManager.Device.Adsl.c \
	introspection/org.freedesktop.NetworkManager.Device.Adsl.h \
	introspection/org.freedesktop.NetworkManager.Device.Bluetooth.c \
	introspection/org.freedesktop.NetworkManager.Device.Bluetooth.h \
	introspection/org.freedesktop.NetworkManager.Device.Bond.c \
	introspection/org.freedesktop.NetworkManager.Device.Bond.h \
	introspection/org.freedesktop.NetworkManager.Device.Bridge.c \
	introspection/org.freedesktop.NetworkManager.Device.Bridge.h \
	introspection/org.freedesktop.NetworkManager.Device.Dummy.c \
	introspection/org.freedesktop.NetworkManager.Device.Dummy.h \
	introspection/org.freedesktop.NetworkManager.Device.Generic.c \
	introspection/org.freedesktop.NetworkManager.Device.Generic.h \
	introspection/org.freedesktop.NetworkManager.Device.IPTunnel.c \
	introspection/org.freedesktop.NetworkManager.Device.IPTunnel.h \
	introspection/org.freedesktop.NetworkManager.Device.Infiniband.c \
	introspection/org.freedesktop.NetworkManager.Device.Infiniband.h \
	introspection/org.freedesktop.NetworkManager.Device.Lowpan.c \
	introspection/org.freedesktop.NetworkManager.Device.Lowpan.h \
	introspection/org.freedesktop.NetworkManager.Device.Macsec.c \
	introspection/org.freedesktop.NetworkManager.Device.Macsec.h \
	introspection/org.freedesktop.NetworkManager.Device.Macvlan.c \
	introspection/org.freedesktop.NetworkManager.Device.Macvlan.h \
	introspection/org.freedesktop.NetworkManager.Device.Modem.c \
	introspection/org.freedesktop.NetworkManager.Device.Modem.h \
	introspection/org.freedesktop.NetworkManager.Device.OlpcMesh.c \
	introspection/org.freedesktop.NetworkManager.Device.OlpcMesh.h \
	introspection/org.freedesktop.NetworkManager.Device.OvsBridge.c \
	introspection/org.freedesktop.NetworkManager.Device.OvsBridge.h \
	introspection/org.freedesktop.NetworkManager.Device.OvsInterface.c \
	introspection/org.freedesktop.NetworkManager.Device.OvsInterface.h \
	introspection/org.freedesktop.NetworkManager.Device.OvsPort.c \
	introspection/org.freedesktop.NetworkManager.Device.OvsPort.h \
	introspection/org.freedesktop.NetworkManager.Device.Ppp.c \
	introspection/org.freedesktop.NetworkManager.Device.Ppp.h \
	introspection/org.freedesktop.NetworkManager.Device.Statistics.c \
	introspection/org.freedesktop.NetworkManager.Device.Statistics.h \
	introspection/org.freedesktop.NetworkManager.Device.Team.c \
	introspection/org.freedesktop.NetworkManager.Device.Team.h \
	introspection/org.freedesktop.NetworkManager.Device.Tun.c \
	introspection/org.freedesktop.NetworkManager.Device.Tun.h \
	introspection/org.freedesktop.NetworkManager.Device.Veth.c \
	introspection/org.freedesktop.NetworkManager.Device.Veth.h \
	introspection/org.freedesktop.NetworkManager.Device.Vlan.c \
	introspection/org.freedesktop.NetworkManager.Device.Vlan.h \
	introspection/org.freedesktop.NetworkManager.Device.Vrf.c \
	introspection/org.freedesktop.NetworkManager.Device.Vrf.h \
	introspection/org.freedesktop.NetworkManager.Device.Vxlan.c \
	introspection/org.freedesktop.NetworkManager.Device.Vxlan.h \
	introspection/org.freedesktop.NetworkManager.Device.WiMax.c \
	introspection/org.freedesktop.NetworkManager.Device.WiMax.h \
	introspection/org.freedesktop.NetworkManager.Device.WifiP2P.c \
	introspection/org.freedesktop.NetworkManager.Device.WifiP2P.h \
	introspection/org.freedesktop.NetworkManager.Device.WireGuard.c \
	introspection/org.freedesktop.NetworkManager.Device.WireGuard.h \
	introspection/org.freedesktop.NetworkManager.Device.Wired.c \
	introspection/org.freedesktop.NetworkManager.Device.Wired.h \
	introspection/org.freedesktop.NetworkManager.Device.Wireless.c \
	introspection/org.freedesktop.NetworkManager.Device.Wireless.h \
	introspection/org.freedesktop.NetworkManager.Device.Wpan.c \
	introspection/org.freedesktop.NetworkManager.Device.Wpan.h \
	introspection/org.freedesktop.NetworkManager.Device.c \
	introspection/org.freedesktop.NetworkManager.Device.h \
	introspection/org.freedesktop.NetworkManager.DnsManager.c \
	introspection/org.freedesktop.NetworkManager.DnsManager.h \
	introspection/org.freedesktop.NetworkManager.IP4Config.c \
	introspection/org.freedesktop.NetworkManager.IP4Config.h \
	introspection/org.freedesktop.NetworkManager.IP6Config.c \
	introspection/org.freedesktop.NetworkManager.IP6Config.h \
	introspection/org.freedesktop.NetworkManager.WifiP2PPeer.c \
	introspection/org.freedesktop.NetworkManager.WifiP2PPeer.h \
	introspection/org.freedesktop.NetworkManager.PPP.c \
	introspection/org.freedesktop.NetworkManager.PPP.h \
	introspection/org.freedesktop.NetworkManager.SecretAgent.c \
	introspection/org.freedesktop.NetworkManager.SecretAgent.h \
	introspection/org.freedesktop.NetworkManager.Settings.Connection.c \
	introspection/org.freedesktop.NetworkManager.Settings.Connection.h \
	introspection/org.freedesktop.NetworkManager.Settings.c \
	introspection/org.freedesktop.NetworkManager.Settings.h \
	introspection/org.freedesktop.NetworkManager.VPN.Connection.c \
	introspection/org.freedesktop.NetworkManager.VPN.Connection.h \
	introspection/org.freedesktop.NetworkManager.VPN.Plugin.c \
	introspection/org.freedesktop.NetworkManager.VPN.Plugin.h \
	introspection/org.freedesktop.NetworkManager.c \
	introspection/org.freedesktop.NetworkManager.h \
	$(NULL)

nodist_introspection_libnmdbus_la_SOURCES = $(introspection_sources)

DBUS_INTERFACE_DOCS = \
	docs/api/dbus-org.freedesktop.NetworkManager.AccessPoint.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.AgentManager.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Checkpoint.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Connection.Active.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.DHCP4Config.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.DHCP6Config.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Adsl.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Bluetooth.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Bond.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Bridge.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Dummy.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Generic.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.IPTunnel.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Infiniband.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Lowpan.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Macsec.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Macvlan.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Modem.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.OlpcMesh.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.OvsBridge.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.OvsInterface.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.OvsPort.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Ppp.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Statistics.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Team.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Tun.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Veth.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Vlan.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Vrf.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Vxlan.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.WiMax.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.WifiP2P.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.WireGuard.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Wired.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Wireless.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Wpan.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Device.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.DnsManager.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.IP4Config.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.IP6Config.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.PPP.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.SecretAgent.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Settings.Connection.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.Settings.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.VPN.Connection.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.VPN.Plugin.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.WifiP2PPeer.xml \
	docs/api/dbus-org.freedesktop.NetworkManager.xml \
	$(NULL)

introspection/%.c: introspection/%.xml
	@$(MKDIR_P) introspection/
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--generate-docbook docs/api/dbus \
		--c-namespace NMDBus \
		--interface-prefix org.freedesktop.NetworkManager \
		$<

introspection/%.h: introspection/%.c
	$()

docs/api/dbus-%.xml: introspection/%.c
	$()

dbusinterfacesdir = $(datadir)/dbus-1/interfaces

dbusinterfaces_DATA = \
	introspection/org.freedesktop.NetworkManager.AccessPoint.xml \
	introspection/org.freedesktop.NetworkManager.AgentManager.xml \
	introspection/org.freedesktop.NetworkManager.Checkpoint.xml \
	introspection/org.freedesktop.NetworkManager.Connection.Active.xml \
	introspection/org.freedesktop.NetworkManager.DHCP4Config.xml \
	introspection/org.freedesktop.NetworkManager.DHCP6Config.xml \
	introspection/org.freedesktop.NetworkManager.Device.Adsl.xml \
	introspection/org.freedesktop.NetworkManager.Device.Bluetooth.xml \
	introspection/org.freedesktop.NetworkManager.Device.Bond.xml \
	introspection/org.freedesktop.NetworkManager.Device.Bridge.xml \
	introspection/org.freedesktop.NetworkManager.Device.Dummy.xml \
	introspection/org.freedesktop.NetworkManager.Device.Generic.xml \
	introspection/org.freedesktop.NetworkManager.Device.IPTunnel.xml \
	introspection/org.freedesktop.NetworkManager.Device.Infiniband.xml \
	introspection/org.freedesktop.NetworkManager.Device.Lowpan.xml \
	introspection/org.freedesktop.NetworkManager.Device.Macsec.xml \
	introspection/org.freedesktop.NetworkManager.Device.Macvlan.xml \
	introspection/org.freedesktop.NetworkManager.Device.Modem.xml \
	introspection/org.freedesktop.NetworkManager.Device.OlpcMesh.xml \
	introspection/org.freedesktop.NetworkManager.Device.OvsBridge.xml \
	introspection/org.freedesktop.NetworkManager.Device.OvsInterface.xml \
	introspection/org.freedesktop.NetworkManager.Device.OvsPort.xml \
	introspection/org.freedesktop.NetworkManager.Device.Ppp.xml \
	introspection/org.freedesktop.NetworkManager.Device.Statistics.xml \
	introspection/org.freedesktop.NetworkManager.Device.Team.xml \
	introspection/org.freedesktop.NetworkManager.Device.Tun.xml \
	introspection/org.freedesktop.NetworkManager.Device.Veth.xml \
	introspection/org.freedesktop.NetworkManager.Device.Vlan.xml \
	introspection/org.freedesktop.NetworkManager.Device.Vrf.xml \
	introspection/org.freedesktop.NetworkManager.Device.Vxlan.xml \
	introspection/org.freedesktop.NetworkManager.Device.WiMax.xml \
	introspection/org.freedesktop.NetworkManager.Device.WifiP2P.xml \
	introspection/org.freedesktop.NetworkManager.Device.WireGuard.xml \
	introspection/org.freedesktop.NetworkManager.Device.Wired.xml \
	introspection/org.freedesktop.NetworkManager.Device.Wireless.xml \
	introspection/org.freedesktop.NetworkManager.Device.Wpan.xml \
	introspection/org.freedesktop.NetworkManager.Device.xml \
	introspection/org.freedesktop.NetworkManager.DnsManager.xml \
	introspection/org.freedesktop.NetworkManager.IP4Config.xml \
	introspection/org.freedesktop.NetworkManager.IP6Config.xml \
	introspection/org.freedesktop.NetworkManager.PPP.xml \
	introspection/org.freedesktop.NetworkManager.SecretAgent.xml \
	introspection/org.freedesktop.NetworkManager.Settings.Connection.xml \
	introspection/org.freedesktop.NetworkManager.Settings.xml \
	introspection/org.freedesktop.NetworkManager.VPN.Connection.xml \
	introspection/org.freedesktop.NetworkManager.VPN.Plugin.xml \
	introspection/org.freedesktop.NetworkManager.WiMax.Nsp.xml \
	introspection/org.freedesktop.NetworkManager.WifiP2PPeer.xml \
	introspection/org.freedesktop.NetworkManager.xml \
	$(NULL)

CLEANFILES += $(introspection_sources)
CLEANFILES += $(DBUS_INTERFACE_DOCS)

$(libnm_libnm_static_la_OBJECTS):               $(introspection_sources)
$(libnm_libnm_la_OBJECTS):                      $(introspection_sources)

EXTRA_DIST += \
	$(dbusinterfaces_DATA) \
	introspection/meson.build

check-docs:
	$(srcdir)/tools/check-docs.sh "$(srcdir)" "$(builddir)"

check_local += check-docs

###############################################################################

libnm_core_lib_h_pub_real = \
	shared/nm-version-macros.h \
	libnm-core/nm-connection.h \
	libnm-core/nm-core-types.h \
	libnm-core/nm-dbus-interface.h \
	libnm-core/nm-errors.h \
	libnm-core/nm-keyfile.h \
	libnm-core/nm-setting-6lowpan.h \
	libnm-core/nm-setting-8021x.h \
	libnm-core/nm-setting-adsl.h \
	libnm-core/nm-setting-bluetooth.h \
	libnm-core/nm-setting-bond.h \
	libnm-core/nm-setting-bridge-port.h \
	libnm-core/nm-setting-bridge.h \
	libnm-core/nm-setting-cdma.h \
	libnm-core/nm-setting-connection.h \
	libnm-core/nm-setting-dcb.h \
	libnm-core/nm-setting-dummy.h \
	libnm-core/nm-setting-ethtool.h \
	libnm-core/nm-setting-generic.h \
	libnm-core/nm-setting-gsm.h \
	libnm-core/nm-setting-hostname.h \
	libnm-core/nm-setting-infiniband.h \
	libnm-core/nm-setting-ip-config.h \
	libnm-core/nm-setting-ip-tunnel.h \
	libnm-core/nm-setting-ip4-config.h \
	libnm-core/nm-setting-ip6-config.h \
	libnm-core/nm-setting-macsec.h \
	libnm-core/nm-setting-macvlan.h \
	libnm-core/nm-setting-match.h \
	libnm-core/nm-setting-olpc-mesh.h \
	libnm-core/nm-setting-ovs-bridge.h \
	libnm-core/nm-setting-ovs-dpdk.h \
	libnm-core/nm-setting-ovs-external-ids.h \
	libnm-core/nm-setting-ovs-interface.h \
	libnm-core/nm-setting-ovs-patch.h \
	libnm-core/nm-setting-ovs-port.h \
	libnm-core/nm-setting-ppp.h \
	libnm-core/nm-setting-pppoe.h \
	libnm-core/nm-setting-proxy.h \
	libnm-core/nm-setting-serial.h \
	libnm-core/nm-setting-sriov.h \
	libnm-core/nm-setting-tc-config.h \
	libnm-core/nm-setting-team-port.h \
	libnm-core/nm-setting-team.h \
	libnm-core/nm-setting-tun.h \
	libnm-core/nm-setting-user.h \
	libnm-core/nm-setting-veth.h \
	libnm-core/nm-setting-vlan.h \
	libnm-core/nm-setting-vpn.h \
	libnm-core/nm-setting-vrf.h \
	libnm-core/nm-setting-vxlan.h \
	libnm-core/nm-setting-wifi-p2p.h \
	libnm-core/nm-setting-wimax.h \
	libnm-core/nm-setting-wired.h \
	libnm-core/nm-setting-wireguard.h \
	libnm-core/nm-setting-wireless-security.h \
	libnm-core/nm-setting-wireless.h \
	libnm-core/nm-setting-wpan.h \
	libnm-core/nm-setting.h \
	libnm-core/nm-simple-connection.h \
	libnm-core/nm-utils.h \
	libnm-core/nm-version.h \
	libnm-core/nm-vpn-dbus-interface.h \
	libnm-core/nm-vpn-editor-plugin.h \
	libnm-core/nm-vpn-plugin-info.h \
	$(NULL)
libnm_core_lib_h_pub_mkenums = \
	libnm-core/nm-core-enum-types.h \
	$(NULL)
libnm_core_lib_h_priv = \
	shared/nm-meta-setting.h \
	libnm-core/nm-connection-private.h \
	libnm-core/nm-core-internal.h \
	libnm-core/nm-core-types-internal.h \
	libnm-core/nm-crypto-impl.h \
	libnm-core/nm-crypto.h \
	libnm-core/nm-property-compare.h \
	libnm-core/nm-setting-private.h \
	libnm-core/nm-team-utils.h \
	libnm-core/nm-utils-private.h \
	$(NULL)
libnm_core_lib_c_settings_real = \
	libnm-core/nm-setting-6lowpan.c \
	libnm-core/nm-setting-8021x.c \
	libnm-core/nm-setting-adsl.c \
	libnm-core/nm-setting-bluetooth.c \
	libnm-core/nm-setting-bond.c \
	libnm-core/nm-setting-bridge-port.c \
	libnm-core/nm-setting-bridge.c \
	libnm-core/nm-setting-cdma.c \
	libnm-core/nm-setting-connection.c \
	libnm-core/nm-setting-dcb.c \
	libnm-core/nm-setting-dummy.c \
	libnm-core/nm-setting-ethtool.c \
	libnm-core/nm-setting-generic.c \
	libnm-core/nm-setting-gsm.c \
	libnm-core/nm-setting-hostname.c \
	libnm-core/nm-setting-infiniband.c \
	libnm-core/nm-setting-ip-config.c \
	libnm-core/nm-setting-ip-tunnel.c \
	libnm-core/nm-setting-ip4-config.c \
	libnm-core/nm-setting-ip6-config.c \
	libnm-core/nm-setting-macsec.c \
	libnm-core/nm-setting-macvlan.c \
	libnm-core/nm-setting-match.c \
	libnm-core/nm-setting-olpc-mesh.c \
	libnm-core/nm-setting-ovs-bridge.c \
	libnm-core/nm-setting-ovs-dpdk.c \
	libnm-core/nm-setting-ovs-external-ids.c \
	libnm-core/nm-setting-ovs-interface.c \
	libnm-core/nm-setting-ovs-patch.c \
	libnm-core/nm-setting-ovs-port.c \
	libnm-core/nm-setting-ppp.c \
	libnm-core/nm-setting-pppoe.c \
	libnm-core/nm-setting-proxy.c \
	libnm-core/nm-setting-serial.c \
	libnm-core/nm-setting-sriov.c \
	libnm-core/nm-setting-tc-config.c \
	libnm-core/nm-setting-team-port.c \
	libnm-core/nm-setting-team.c \
	libnm-core/nm-setting-tun.c \
	libnm-core/nm-setting-user.c \
	libnm-core/nm-setting-veth.c \
	libnm-core/nm-setting-vlan.c \
	libnm-core/nm-setting-vpn.c \
	libnm-core/nm-setting-vrf.c \
	libnm-core/nm-setting-vxlan.c \
	libnm-core/nm-setting-wifi-p2p.c \
	libnm-core/nm-setting-wimax.c \
	libnm-core/nm-setting-wired.c \
	libnm-core/nm-setting-wireguard.c \
	libnm-core/nm-setting-wireless-security.c \
	libnm-core/nm-setting-wireless.c \
	libnm-core/nm-setting-wpan.c \
	$(NULL)
libnm_core_lib_c_real = \
	$(libnm_core_lib_c_settings_real) \
	shared/nm-meta-setting.c \
	libnm-core/nm-connection.c \
	libnm-core/nm-crypto.c \
	libnm-core/nm-dbus-utils.c \
	libnm-core/nm-errors.c \
	libnm-core/nm-property-compare.c \
	libnm-core/nm-setting.c \
	libnm-core/nm-simple-connection.c \
	libnm-core/nm-team-utils.c \
	libnm-core/nm-utils.c \
	libnm-core/nm-vpn-editor-plugin.c \
	libnm-core/nm-vpn-plugin-info.c \
	$(NULL)

libnm_core_lib_c_mkenums = \
	libnm-core/nm-core-enum-types.c

libnminclude_HEADERS += \
	$(libnm_core_lib_h_pub_real)

nodist_libnminclude_HEADERS += \
	$(libnm_core_lib_h_pub_mkenums)

###############################################################################

dflt_cppflags_libnm_core = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	-I$(builddir)/shared \
	-I$(srcdir)/libnm-core \
	-I$(builddir)/libnm-core \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(LIBUDEV_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

noinst_LTLIBRARIES += libnm-core/libnm-core.la

GLIB_GENERATED += \
	$(libnm_core_lib_h_pub_mkenums) \
	$(libnm_core_lib_c_mkenums)
nm_core_enum_types_sources = $(libnm_core_lib_h_pub_real)

nm_core_enum_types_MKENUMS_C_FLAGS = --identifier-prefix NM --fhead '\#include "nm-default.h"\n'

libnm-core/nm-core-enum-types.h.stamp:                                      libnm-core/.dirstamp
libnm-core/nm-core-enum-types.c.stamp:                                      libnm-core/.dirstamp

$(dispatcher_libnm_dispatcher_core_la_OBJECTS):                             $(libnm_core_lib_h_pub_mkenums)
$(dispatcher_nm_dispatcher_OBJECTS):                                        $(libnm_core_lib_h_pub_mkenums)
$(libnm_core_libnm_core_la_OBJECTS):                                        $(libnm_core_lib_h_pub_mkenums)
$(libnm_libnm_la_OBJECTS):                                                  $(libnm_core_lib_h_pub_mkenums)
$(libnm_tests_libnm_vpn_plugin_utils_test_la_OBJECTS):                      $(libnm_core_lib_h_pub_mkenums)
$(src_core_NetworkManager_OBJECTS):                                         $(libnm_core_lib_h_pub_mkenums)
$(src_core_devices_adsl_libnm_device_plugin_adsl_la_OBJECTS):               $(libnm_core_lib_h_pub_mkenums)
$(src_core_devices_bluetooth_libnm_device_plugin_bluetooth_la_OBJECTS):     $(libnm_core_lib_h_pub_mkenums)
$(src_core_devices_team_libnm_device_plugin_team_la_OBJECTS):               $(libnm_core_lib_h_pub_mkenums)
$(src_core_devices_wifi_libnm_device_plugin_wifi_la_OBJECTS):               $(libnm_core_lib_h_pub_mkenums)
$(src_core_devices_wwan_libnm_device_plugin_wwan_la_OBJECTS):               $(libnm_core_lib_h_pub_mkenums)
$(src_core_devices_ovs_libnm_device_plugin_ovs_la_OBJECTS):                 $(libnm_core_lib_h_pub_mkenums)

libnm_core_libnm_core_la_CPPFLAGS = \
	$(dflt_cppflags_libnm_core) \
	-DG_LOG_DOMAIN=\""libnm"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIBNM_CORE \
	$(NULL)

libnm_core_libnm_core_la_SOURCES = \
	$(libnm_core_lib_h_pub_real) \
	$(libnm_core_lib_h_priv) \
	$(libnm_core_lib_c_real)

nodist_libnm_core_libnm_core_la_SOURCES = \
	$(libnm_core_lib_h_pub_mkenums) \
	$(libnm_core_lib_c_mkenums)

libnm_core_libnm_core_la_LIBADD = \
	$(GLIB_LIBS) \
	$(UUID_LIBS) \
	$(NULL)

libnm_core_libnm_core_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

EXTRA_DIST += \
	libnm-core/nm-crypto-gnutls.c \
	libnm-core/nm-crypto-nss.c \
	libnm-core/nm-core-enum-types.c.template \
	libnm-core/nm-core-enum-types.h.template \
	libnm-core/meson.build \
	$(NULL)

libnm-core/nm-vpn-dbus-types.xml: libnm-core/nm-vpn-dbus-interface.h tools/enums-to-docbook.pl
	@$(MKDIR_P) libnm-core/
	$(AM_V_GEN) @PERL@ $(srcdir)/tools/enums-to-docbook.pl 'nm-vpn-dbus-types' 'VPN Plugin D-Bus API Types' $< >$@

libnm-core/nm-dbus-types.xml: libnm-core/nm-dbus-interface.h tools/enums-to-docbook.pl
	@$(MKDIR_P) libnm-core/
	$(AM_V_GEN) @PERL@ $(srcdir)/tools/enums-to-docbook.pl 'nm-dbus-types' 'NetworkManager D-Bus API Types' $< >$@

BUILT_SOURCES += \
	libnm-core/nm-vpn-dbus-types.xml \
	libnm-core/nm-dbus-types.xml

dist_dependencies += \
	libnm-core/nm-vpn-dbus-types.xml \
	libnm-core/nm-dbus-types.xml

###############################################################################

if HAVE_CRYPTO_GNUTLS
if WITH_GNUTLS
libnm_crypto_lib = libnm-core/libnm-crypto-gnutls.la
else
check_ltlibraries += libnm-core/libnm-crypto-gnutls.la
endif

libnm_core_libnm_crypto_gnutls_la_SOURCES = libnm-core/nm-crypto-gnutls.c
libnm_core_libnm_crypto_gnutls_la_CPPFLAGS = \
	$(libnm_core_libnm_core_la_CPPFLAGS) \
	$(GNUTLS_CFLAGS)
libnm_core_libnm_crypto_gnutls_la_LDFLAGS = \
	$(libnm_core_libnm_core_la_LDFLAGS)
libnm_core_libnm_crypto_gnutls_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GNUTLS_LIBS)
endif

if HAVE_CRYPTO_NSS
if WITH_NSS
libnm_crypto_lib = libnm-core/libnm-crypto-nss.la
else
check_ltlibraries += libnm-core/libnm-crypto-nss.la
endif

libnm_core_libnm_crypto_nss_la_SOURCES = libnm-core/nm-crypto-nss.c
libnm_core_libnm_crypto_nss_la_CPPFLAGS = \
	$(libnm_core_libnm_core_la_CPPFLAGS) \
	$(NSS_CFLAGS)
libnm_core_libnm_crypto_nss_la_LDFLAGS = \
	$(libnm_core_libnm_core_la_LDFLAGS)
libnm_core_libnm_crypto_nss_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NSS_LIBS)
endif

noinst_LTLIBRARIES += $(libnm_crypto_lib)

###############################################################################

check_programs += \
	libnm-core/tests/test-compare \
	libnm-core/tests/test-crypto \
	libnm-core/tests/test-general \
	libnm-core/tests/test-keyfile \
	libnm-core/tests/test-secrets \
	libnm-core/tests/test-setting \
	libnm-core/tests/test-settings-defaults

GLIB_GENERATED += \
	libnm-core/tests/nm-core-tests-enum-types.h \
	libnm-core/tests/nm-core-tests-enum-types.c
nm_core_tests_enum_types_sources = libnm-core/tests/test-general-enums.h
nm_core_tests_enum_types_MKENUMS_C_FLAGS = --fhead '\#include "nm-default.h"\n'

libnm-core/tests/nm-core-tests-enum-types.h.stamp: libnm-core/tests/.dirstamp
libnm-core/tests/nm-core-tests-enum-types.c.stamp: libnm-core/tests/.dirstamp

$(libnm_core_tests_test_general_OBJECTS): libnm-core/tests/nm-core-tests-enum-types.h

libnm_core_tests_cppflags = \
	-I$(srcdir)/libnm-core/tests \
	-I$(builddir)/libnm-core/tests \
	$(dflt_cppflags_libnm_core) \
	-DNETWORKMANAGER_COMPILATION_TEST \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIBNM_CORE \
	$(SANITIZER_EXEC_CFLAGS) \
	$(NULL)

libnm_core_tests_test_compare_CPPFLAGS = $(libnm_core_tests_cppflags)
libnm_core_tests_test_crypto_CPPFLAGS = $(libnm_core_tests_cppflags)
libnm_core_tests_test_general_CPPFLAGS = $(libnm_core_tests_cppflags)
libnm_core_tests_test_keyfile_CPPFLAGS = $(libnm_core_tests_cppflags)
libnm_core_tests_test_secrets_CPPFLAGS = $(libnm_core_tests_cppflags)
libnm_core_tests_test_setting_CPPFLAGS = $(libnm_core_tests_cppflags)
libnm_core_tests_test_settings_defaults_CPPFLAGS = $(libnm_core_tests_cppflags)

libnm_core_tests_test_general_SOURCES = \
	libnm-core/tests/test-general-enums.h \
	libnm-core/tests/test-general.c \
	$(NULL)

nodist_libnm_core_tests_test_general_SOURCES = \
	libnm-core/tests/nm-core-tests-enum-types.c \
	libnm-core/tests/nm-core-tests-enum-types.h \
	$(NULL)

libnm_core_tests_ldadd = \
	libnm-core/nm-libnm-core-aux/libnm-libnm-core-aux.la \
	libnm-core/nm-keyfile/libnm-keyfile.la \
	libnm-core/libnm-core.la \
	$(libnm_crypto_lib) \
	libnm-core/nm-libnm-core-intern/libnm-libnm-core-intern.la \
	shared/nm-base/libnm-base.la \
	shared/systemd/libnm-systemd-shared.la \
	shared/systemd/libnm-systemd-logging-stub.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	$(GLIB_LIBS) \
	$(NULL)

libnm_core_tests_ldflags = \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

libnm_core_tests_test_compare_LDADD = $(libnm_core_tests_ldadd)
libnm_core_tests_test_crypto_LDADD = $(libnm_core_tests_ldadd)
libnm_core_tests_test_general_LDADD = $(libnm_core_tests_ldadd)
libnm_core_tests_test_keyfile_LDADD = $(libnm_core_tests_ldadd)
libnm_core_tests_test_secrets_LDADD = $(libnm_core_tests_ldadd)
libnm_core_tests_test_setting_LDADD = $(libnm_core_tests_ldadd)
libnm_core_tests_test_settings_defaults_LDADD = $(libnm_core_tests_ldadd)

libnm_core_tests_test_compare_LDFLAGS = $(libnm_core_tests_ldflags)
libnm_core_tests_test_crypto_LDFLAGS = $(libnm_core_tests_ldflags)
libnm_core_tests_test_general_LDFLAGS = $(libnm_core_tests_ldflags)
libnm_core_tests_test_keyfile_LDFLAGS = $(libnm_core_tests_ldflags)
libnm_core_tests_test_secrets_LDFLAGS = $(libnm_core_tests_ldflags)
libnm_core_tests_test_setting_LDFLAGS = $(libnm_core_tests_ldflags)
libnm_core_tests_test_settings_defaults_LDFLAGS = $(libnm_core_tests_ldflags)

$(libnm_core_tests_test_compare_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(libnm_core_tests_test_crypto_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(libnm_core_tests_test_general_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(libnm_core_tests_test_keyfile_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(libnm_core_tests_test_secrets_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(libnm_core_tests_test_setting_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(libnm_core_tests_test_settings_defaults_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

# test-cert.p12 created with:
#
# openssl pkcs12 -export \
#    -in test_key_and_cert.pem \
#    -inkey test_key_and_cert.pem \
#    -certfile test_ca_cert.pem \
#    -name "test-pkcs12" \
#    -out test-cert.p12

EXTRA_DIST += \
	libnm-core/tests/certs/ca-no-ending-newline.pem \
	libnm-core/tests/certs/pkcs8-decrypted.der \
	libnm-core/tests/certs/pkcs8-enc-key.pem \
	libnm-core/tests/certs/pkcs8-noenc-key.pem \
	libnm-core/tests/certs/test2_ca_cert.pem \
	libnm-core/tests/certs/test2-cert.p12 \
	libnm-core/tests/certs/test2_key_and_cert.pem \
	libnm-core/tests/certs/test-aes-128-key.pem \
	libnm-core/tests/certs/test-aes-256-key.pem \
	libnm-core/tests/certs/test_ca_cert.der \
	libnm-core/tests/certs/test_ca_cert.pem \
	libnm-core/tests/certs/test-ca-cert.pem \
	libnm-core/tests/certs/test-cert.p12 \
	libnm-core/tests/certs/test_key_and_cert.pem \
	libnm-core/tests/certs/test-key-and-cert.pem \
	libnm-core/tests/certs/test-key-only-decrypted.der \
	libnm-core/tests/certs/test-key-only-decrypted.pem \
	libnm-core/tests/certs/test-key-only.pem \
	libnm-core/tests/certs/test-tpm2wrapped-key.pem \
	libnm-core/tests/nm-core-tests-enum-types.c.template \
	libnm-core/tests/nm-core-tests-enum-types.h.template \
	libnm-core/tests/meson.build

###############################################################################

libnm_lib_h_pub_real = \
	shared/nm-version-macros.h \
	libnm/NetworkManager.h \
	libnm/nm-access-point.h \
	libnm/nm-active-connection.h \
	libnm/nm-autoptr.h \
	libnm/nm-checkpoint.h \
	libnm/nm-client.h \
	libnm/nm-device-6lowpan.h \
	libnm/nm-device-adsl.h \
	libnm/nm-device-bond.h \
	libnm/nm-device-bridge.h \
	libnm/nm-device-bt.h \
	libnm/nm-device-dummy.h \
	libnm/nm-device-ethernet.h \
	libnm/nm-device-generic.h \
	libnm/nm-device-infiniband.h \
	libnm/nm-device-ip-tunnel.h \
	libnm/nm-device-macsec.h \
	libnm/nm-device-macvlan.h \
	libnm/nm-device-modem.h \
	libnm/nm-device-olpc-mesh.h \
	libnm/nm-device-ovs-bridge.h \
	libnm/nm-device-ovs-interface.h \
	libnm/nm-device-ovs-port.h \
	libnm/nm-device-ppp.h \
	libnm/nm-device-team.h \
	libnm/nm-device-tun.h \
	libnm/nm-device-veth.h \
	libnm/nm-device-vlan.h \
	libnm/nm-device-vrf.h \
	libnm/nm-device-vxlan.h \
	libnm/nm-device-wifi-p2p.h \
	libnm/nm-device-wifi.h \
	libnm/nm-device-wimax.h \
	libnm/nm-device-wireguard.h \
	libnm/nm-device-wpan.h \
	libnm/nm-device.h \
	libnm/nm-dhcp-config.h \
	libnm/nm-ethtool-utils.h \
	libnm/nm-ip-config.h \
	libnm/nm-object.h \
	libnm/nm-remote-connection.h \
	libnm/nm-secret-agent-old.h \
	libnm/nm-types.h \
	libnm/nm-vpn-connection.h \
	libnm/nm-vpn-editor.h \
	libnm/nm-vpn-plugin-old.h \
	libnm/nm-vpn-service-plugin.h \
	libnm/nm-wifi-p2p-peer.h \
	libnm/nm-wimax-nsp.h
libnm_lib_h_pub_mkenums = \
	libnm/nm-enum-types.h
libnm_lib_h_priv = \
	libnm/nm-libnm-utils.h \
	libnm/nm-dbus-helpers.h \
	libnm/nm-device-private.h \
	libnm/nm-dhcp4-config.h \
	libnm/nm-dhcp6-config.h \
	libnm/nm-dns-manager.h \
	libnm/nm-ip4-config.h \
	libnm/nm-ip6-config.h \
	libnm/nm-object-private.h \
	libnm/nm-remote-connection-private.h \
	$(NULL)
libnm_lib_c_real = \
	libnm/nm-client.c \
	libnm/nm-object.c \
	libnm/nm-device.c \
	libnm/nm-active-connection.c \
	\
	libnm/nm-access-point.c \
	libnm/nm-checkpoint.c \
	libnm/nm-dbus-helpers.c \
	libnm/nm-device-6lowpan.c \
	libnm/nm-device-adsl.c \
	libnm/nm-device-bond.c \
	libnm/nm-device-bridge.c \
	libnm/nm-device-bt.c \
	libnm/nm-device-dummy.c \
	libnm/nm-device-ethernet.c \
	libnm/nm-device-generic.c \
	libnm/nm-device-infiniband.c \
	libnm/nm-device-ip-tunnel.c \
	libnm/nm-device-macsec.c \
	libnm/nm-device-macvlan.c \
	libnm/nm-device-modem.c \
	libnm/nm-device-olpc-mesh.c \
	libnm/nm-device-ovs-bridge.c \
	libnm/nm-device-ovs-interface.c \
	libnm/nm-device-ovs-port.c \
	libnm/nm-device-ppp.c \
	libnm/nm-device-team.c \
	libnm/nm-device-tun.c \
	libnm/nm-device-veth.c \
	libnm/nm-device-vlan.c \
	libnm/nm-device-vrf.c \
	libnm/nm-device-vxlan.c \
	libnm/nm-device-wifi-p2p.c \
	libnm/nm-device-wifi.c \
	libnm/nm-device-wimax.c \
	libnm/nm-device-wireguard.c \
	libnm/nm-device-wpan.c \
	libnm/nm-dhcp-config.c \
	libnm/nm-dhcp4-config.c \
	libnm/nm-dhcp6-config.c \
	libnm/nm-dns-manager.c \
	libnm/nm-ip-config.c \
	libnm/nm-ip4-config.c \
	libnm/nm-ip6-config.c \
	libnm/nm-libnm-utils.c \
	libnm/nm-remote-connection.c \
	libnm/nm-secret-agent-old.c \
	libnm/nm-vpn-connection.c \
	libnm/nm-vpn-editor.c \
	libnm/nm-vpn-plugin-old.c \
	libnm/nm-vpn-service-plugin.c \
	libnm/nm-wifi-p2p-peer.c \
	libnm/nm-wimax-nsp.c \
	$(NULL)
libnm_lib_c_mkenums = \
	libnm/nm-enum-types.c

libnm_lib_cppflags = \
	-I$(srcdir)/libnm \
	-I$(builddir)/libnm \
	$(dflt_cppflags_libnm_core) \
	-DG_LOG_DOMAIN=\""libnm"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIBNM \
	$(NULL)

libnminclude_HEADERS += \
	$(libnm_lib_h_pub_real)

nodist_libnminclude_HEADERS += \
	$(libnm_lib_h_pub_mkenums)

###############################################################################

noinst_LTLIBRARIES += libnm/libnm_static.la

libnm_libnm_static_la_CPPFLAGS = \
	$(INTROSPECTION_CFLAGS) \
	$(libnm_lib_cppflags) \
	$(NULL)

libnm_libnm_static_la_SOURCES = \
	$(libnm_lib_c_real) \
	$(NULL)

nodist_libnm_libnm_static_la_SOURCES = \
	$(libnm_lib_h_pub_mkenums) \
	$(libnm_lib_c_mkenums) \
	$(NULL)

libnm_libnm_static_la_LIBADD = \
	libnm-core/nm-libnm-core-aux/libnm-libnm-core-aux.la \
	libnm-core/nm-keyfile/libnm-keyfile.la \
	libnm-core/libnm-core.la \
	$(libnm_crypto_lib) \
	libnm-core/nm-libnm-core-intern/libnm-libnm-core-intern.la \
	shared/nm-base/libnm-base.la \
	introspection/libnmdbus.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/systemd/libnm-systemd-shared.la \
	shared/systemd/libnm-systemd-logging-stub.la \
	shared/nm-udev-aux/libnm-udev-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	$(GLIB_LIBS) \
	$(DL_LIBS) \
	$(UUID_LIBS) \
	$(LIBUDEV_LIBS) \
	$(NULL)

$(libnm_libnm_static_la_OBJECTS) : $(libnm_lib_h_pub_mkenums)
$(libnm_libnm_static_la_OBJECTS) : $(libnm_core_lib_h_pub_mkenums)

###############################################################################

lib_LTLIBRARIES += libnm/libnm.la

GLIB_GENERATED += \
	$(libnm_lib_h_pub_mkenums) \
	$(libnm_lib_c_mkenums)
nm_enum_types_sources = \
	$(libnm_lib_h_pub_mkenums) \
	$(libnm_lib_h_pub_real)
nm_enum_types_MKENUMS_H_FLAGS = --identifier-prefix NM --fhead '\#include "nm-core-enum-types.h"\n'
nm_enum_types_MKENUMS_C_FLAGS = --identifier-prefix NM --fhead '\#include "nm-default.h"\n'

$(dispatcher_nm_dispatcher_OBJECTS):                    $(libnm_lib_h_pub_mkenums)
$(dispatcher_libnm_dispatcher_core_la_OBJECTS):         $(libnm_lib_h_pub_mkenums)
$(libnm_libnm_la_OBJECTS):                              $(libnm_lib_h_pub_mkenums)
$(libnm_tests_libnm_vpn_plugin_utils_test_la_OBJECTS):  $(libnm_core_lib_h_pub_mkenums)

libnm_libnm_la_CPPFLAGS = \
	$(libnm_lib_cppflags) \
	$(LIBUDEV_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

libnm_libnm_la_SOURCES = \
	$(libnm_lib_h_pub_real) \
	$(libnm_lib_h_priv) \
	$(NULL)

EXTRA_libnm_libnm_la_DEPENDENCIES = \
	libnm/libnm.ver

libnm_libnm_la_LIBADD = \
	libnm/libnm_static.la \
	$(NULL)

libnm_libnm_la_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/libnm/libnm.ver" \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	-version-info "1:0:1"

check-local-exports-libnm: libnm/libnm.la
	$(srcdir)/tools/check-exports.sh "$(builddir)/libnm/.libs/libnm.so" "$(srcdir)/libnm/libnm.ver"

check_local += check-local-exports-libnm

pkgconfig_DATA += libnm/libnm.pc

DISTCLEANFILES += \
	libnm/libnm.pc

EXTRA_DIST += \
	libnm/libnm.pc.in \
	libnm/libnm.ver

libnm_NM_1_0_typelib =

if HAVE_INTROSPECTION
libnm_NM_1_0_typelib += libnm/NM-1.0.typelib

libnm/NM-1.0.gir: libnm/libnm.la
libnm_NM_1_0_gir_INCLUDES = Gio-2.0
libnm_NM_1_0_gir_PACKAGES = gio-2.0
libnm_NM_1_0_gir_EXPORT_PACKAGES = libnm
libnm_NM_1_0_gir_CFLAGS = $(libnm_libnm_la_CPPFLAGS)
libnm_NM_1_0_gir_LIBS = libnm/libnm.la
libnm_NM_1_0_gir_FILES = \
	$(libnm_core_lib_h_pub_mkenums) \
	$(libnm_core_lib_h_pub_real) \
	$(libnm_core_lib_c_mkenums) \
	$(libnm_core_lib_c_real) \
	$(libnm_lib_h_pub_mkenums) \
	$(libnm_lib_h_pub_real) \
	libnm-core/nm-keyfile/nm-keyfile.c \
	$(libnm_lib_c_mkenums) \
	$(libnm_lib_c_real)
libnm_NM_1_0_gir_SCANNERFLAGS = --warn-all --identifier-prefix=NM --symbol-prefix=nm

libnm/libnm.typelib: libnm/libnm.gir
	$(INTROSPECTION_COMPILER) --includedir=$(srcdir)/libnm-core --includedir=$(builddir)/libnm-core --includedir=$(srcdir)/libnm --includedir=$(builddir)/libnm $< -o $@

INTROSPECTION_GIRS += libnm/NM-1.0.gir

libnm_noinst_data = \
	clients/cli/generate-docs-nm-settings-nmcli.xml \
	libnm/nm-property-infos-dbus.xml \
	libnm/nm-property-infos-ifcfg-rh.xml \
	libnm/nm-property-infos-keyfile.xml \
	libnm/nm-property-infos-nmcli.xml \
	libnm/nm-settings-docs-gir.xml \
	man/nm-settings-docs-dbus.xml \
	man/nm-settings-docs-nmcli.xml \
	$(NULL)

noinst_DATA += $(libnm_noinst_data)

EXTRA_DIST += clients/cli/generate-docs-nm-settings-nmcli.xml.in

if BUILD_DOCS
clients/cli/generate-docs-nm-settings-nmcli.xml: clients/cli/generate-docs-nm-settings-nmcli
	$(AM_V_GEN) clients/cli/generate-docs-nm-settings-nmcli > "$@"
check-local-generate-docs-nm-settings-nmcli: clients/cli/generate-docs-nm-settings-nmcli.xml
	$(srcdir)/tools/check-compare-generated.sh "$(srcdir)" "$(builddir)" "$<"
check_local += check-local-generate-docs-nm-settings-nmcli
DISTCLEANFILES += clients/cli/generate-docs-nm-settings-nmcli.xml
else
clients/cli/generate-docs-nm-settings-nmcli.xml: clients/cli/generate-docs-nm-settings-nmcli.xml.in
	$(AM_V_GEN) cp $^ $@
check-local-generate-docs-nm-settings-nmcli:
endif

libnm_docs_sources = $(libnm_core_lib_c_settings_real)

libnm/nm-property-infos-%.xml: tools/generate-docs-nm-property-infos.pl $(libnm_docs_sources)
	$(AM_V_GEN) $(srcdir)/tools/generate-docs-nm-property-infos.pl $(patsubst nm-property-infos-%.xml,%,$(notdir $@)) $@ $(filter-out $<,$^)

libnm/nm-settings-docs-gir.xml: tools/generate-docs-nm-settings-docs-gir.py libnm/NM-1.0.gir libnm/NM-1.0.typelib libnm/libnm.la $(libnm_docs_sources)
	$(AM_V_GEN) \
	export GI_TYPELIB_PATH=$(abs_builddir)/libnm$${GI_TYPELIB_PATH:+:$$GI_TYPELIB_PATH}; \
	export LD_LIBRARY_PATH=$(abs_builddir)/libnm/.libs$${LD_LIBRARY_PATH:+:$$LD_LIBRARY_PATH}; \
	$(call set_sanitizer_env,$(abs_builddir)/libnm/.libs/libnm.so); \
	"$(PYTHON)" \
	$(srcdir)/tools/generate-docs-nm-settings-docs-gir.py \
		--gir $(builddir)/libnm/NM-1.0.gir \
		--output $@

man/nm-settings-docs-nmcli.xml: clients/cli/generate-docs-nm-settings-nmcli.xml libnm/nm-property-infos-nmcli.xml libnm/nm-settings-docs-gir.xml tools/generate-docs-nm-settings-docs-merge.py man/common.ent
	$(AM_V_GEN) "$(PYTHON)" $(srcdir)/tools/generate-docs-nm-settings-docs-merge.py --only-from-first $@ $(wordlist 1,3,$^)

man/nm-settings-docs-%.xml: libnm/nm-property-infos-%.xml libnm/nm-settings-docs-gir.xml tools/generate-docs-nm-settings-docs-merge.py man/common.ent
	$(AM_V_GEN) "$(PYTHON)" $(srcdir)/tools/generate-docs-nm-settings-docs-merge.py $@ $(wordlist 1,2,$^)

EXTRA_DIST += $(libnm_noinst_data)
DISTCLEANFILES += $(libnm_noinst_data)

endif

EXTRA_DIST += \
	tools/generate-docs-nm-property-infos.pl \
	tools/generate-docs-nm-settings-docs-merge.py \
	tools/generate-docs-nm-settings-docs-gir.py \
	libnm/meson.build \
	libnm/nm-enum-types.c.template \
	libnm/nm-enum-types.h.template \
	$(NULL)

###############################################################################

check_programs += libnm/tests/test-libnm

libnm_tests_programs_req_introspection = \
	libnm/tests/test-nm-client \
	libnm/tests/test-remote-settings-client \
	libnm/tests/test-secret-agent

if HAVE_INTROSPECTION
check_programs += $(libnm_tests_programs_req_introspection)
else
check_programs_norun += $(libnm_tests_programs_req_introspection)
endif

libnm_tests_cppflags = \
	-I$(srcdir)/libnm \
	-I$(builddir)/libnm \
	$(dflt_cppflags_libnm_core) \
	-DNETWORKMANAGER_COMPILATION_TEST \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIBNM \
	$(SANITIZER_EXEC_CFLAGS) \
	$(NULL)

libnm_tests_ldadd = \
	libnm/libnm_static.la \
	$(GLIB_LIBS) \
	$(NULL)

libnm_tests_ldflags = \
	$(SANITIZER_EXEC_LDFLAGS)

libnm_tests_test_libnm_CPPFLAGS = $(libnm_tests_cppflags)
libnm_tests_test_nm_client_CPPFLAGS = $(libnm_tests_cppflags)
libnm_tests_test_remote_settings_client_CPPFLAGS = $(libnm_tests_cppflags)
libnm_tests_test_secret_agent_CPPFLAGS = $(libnm_tests_cppflags)

libnm_tests_test_libnm_SOURCES = \
	shared/nm-utils/nm-compat.c \
	libnm/tests/test-libnm.c \
	$(NULL)

libnm_tests_test_nm_client_SOURCES = \
	shared/nm-test-utils-impl.c \
	shared/nm-test-libnm-utils.h \
	libnm/tests/test-nm-client.c

libnm_tests_test_remote_settings_client_SOURCES = \
	shared/nm-test-utils-impl.c \
	shared/nm-test-libnm-utils.h \
	libnm/tests/test-remote-settings-client.c

libnm_tests_test_secret_agent_SOURCES = \
	shared/nm-test-utils-impl.c \
	shared/nm-test-libnm-utils.h \
	libnm/tests/test-secret-agent.c

libnm_tests_test_libnm_LDADD = $(libnm_tests_ldadd)
libnm_tests_test_nm_client_LDADD = $(libnm_tests_ldadd)
libnm_tests_test_remote_settings_client_LDADD = $(libnm_tests_ldadd)
libnm_tests_test_secret_agent_LDADD = $(libnm_tests_ldadd)

libnm_tests_test_libnm_LDFLAGS = $(libnm_tests_ldflags)
libnm_tests_test_nm_client_LDFLAGS = $(libnm_tests_ldflags)
libnm_tests_test_remote_settings_client_LDFLAGS = $(libnm_tests_ldflags)
libnm_tests_test_secret_agent_LDFLAGS = $(libnm_tests_ldflags)

$(libnm_tests_test_libnm_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(libnm_tests_test_nm_client_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(libnm_tests_test_remote_settings_client_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(libnm_tests_test_secret_agent_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

# tools/test-networkmanager-service.py uses libnm's typelib. Ensure it
# is built first.
$(libnm_tests_test_nm_client_OBJECTS):              $(libnm_NM_1_0_typelib)
$(libnm_tests_test_remote_settings_client_OBJECTS): $(libnm_NM_1_0_typelib)
$(libnm_tests_test_secret_agent_OBJECTS):           $(libnm_NM_1_0_typelib)

###############################################################################

# just test, that we can build "nm-vpn-plugin-utils.c"

check_ltlibraries += libnm/tests/libnm-vpn-plugin-utils-test.la

libnm_tests_libnm_vpn_plugin_utils_test_la_SOURCES = \
	shared/nm-utils/nm-vpn-plugin-utils.c \
	shared/nm-utils/nm-vpn-plugin-utils.h \
	$(NULL)

libnm_tests_libnm_vpn_plugin_utils_test_la_CFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	-I$(builddir)/shared \
	-I$(srcdir)/libnm-core \
	-I$(builddir)/libnm-core \
	-I$(srcdir)/libnm \
	-I$(builddir)/libnm \
	$(GLIB_CFLAGS) \
	$(SANITIZER_EXEC_CFLAGS) \
	-DNETWORKMANAGER_COMPILATION_TEST \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT \
	$(NULL)

libnm_tests_libnm_vpn_plugin_utils_test_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

EXTRA_DIST += \
	libnm/tests/meson.build

###############################################################################
# src/core/
###############################################################################

src_core_cppflags_base = \
	-I$(srcdir)/src/core \
	$(dflt_cppflags_libnm_core) \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_DAEMON \
	$(SANITIZER_EXEC_CFLAGS) \
	$(NULL)

src_core_cppflags_base_test = \
	$(src_core_cppflags_base) \
	-DNETWORKMANAGER_COMPILATION_TEST \
	$(NULL)

src_core_cppflags_device_plugin = \
	$(src_core_cppflags_base)

src_core_cppflags = \
	$(src_core_cppflags_base) \
	\
	$(LIBNDP_CFLAGS) \
	$(LIBPSL_CFLAGS) \
	$(LIBCURL_CFLAGS) \
	$(SELINUX_CFLAGS) \
	$(LIBAUDIT_CFLAGS) \
	$(SYSTEMD_LOGIN_CFLAGS) \
	$(SYSTEMD_JOURNAL_CFLAGS) \
	\
	$(NULL)

src_core_cppflags_test = \
	$(src_core_cppflags) \
	-DNETWORKMANAGER_COMPILATION_TEST \
	$(NULL)

if REQUIRE_ROOT_TESTS
src_core_cppflags_test += -DREQUIRE_ROOT_TESTS=1
endif

src_core_ldflags = $(CODE_COVERAGE_LDFLAGS)

sbin_PROGRAMS += \
	src/core/NetworkManager

libexec_PROGRAMS += \
	src/core/nm-iface-helper

noinst_LTLIBRARIES += \
	src/core/libNetworkManagerBase.la \
	src/core/libNetworkManager.la \
	src/core/libnm-systemd-core.la \
	$(NULL)

check-config-options:
	$(srcdir)/tools/check-config-options.sh "$(srcdir)"

check_local += check-config-options

###############################################################################

libsystemd_cppflags = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	-I$(builddir)/shared \
	-I$(srcdir)/shared/systemd/ \
	-I$(srcdir)/shared/systemd/sd-adapt-shared \
	-I$(srcdir)/shared/systemd/src/basic \
	-I$(srcdir)/shared/systemd/src/shared \
	$(LIBSYSTEMD_NM_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	$(NULL)

noinst_LTLIBRARIES += shared/systemd/libnm-systemd-logging-stub.la

shared_systemd_libnm_systemd_logging_stub_la_CPPFLAGS = \
	$(libsystemd_cppflags) \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_SYSTEMD_SHARED \
	-DG_LOG_DOMAIN=\""libnm"\" \
	$(NULL)

shared_systemd_libnm_systemd_logging_stub_la_SOURCES = \
	shared/systemd/nm-logging-stub.c \
	$(NULL)

shared_systemd_libnm_systemd_logging_stub_la_LIBADD = \
	$(GLIB_LIBS) \
	$(CODE_COVERAGE_LDFLAGS) \
	$(NULL)

noinst_LTLIBRARIES += shared/systemd/libnm-systemd-shared.la

shared_systemd_libnm_systemd_shared_la_CPPFLAGS = \
	$(libsystemd_cppflags) \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_SYSTEMD_SHARED \
	-DG_LOG_DOMAIN=\""libnm"\" \
	$(NULL)

shared_systemd_libnm_systemd_shared_la_SOURCES = \
	shared/systemd/nm-sd-utils-shared.c \
	shared/systemd/nm-sd-utils-shared.h \
	shared/systemd/sd-adapt-shared/architecture.h \
	shared/systemd/sd-adapt-shared/arphrd-list.h \
	shared/systemd/sd-adapt-shared/blockdev-util.h \
	shared/systemd/sd-adapt-shared/build.h \
	shared/systemd/sd-adapt-shared/copy.h \
	shared/systemd/sd-adapt-shared/def.h \
	shared/systemd/sd-adapt-shared/dhcp-server-internal.h \
	shared/systemd/sd-adapt-shared/dirent-util.h \
	shared/systemd/sd-adapt-shared/errno-list.h \
	shared/systemd/sd-adapt-shared/glob-util.h \
	shared/systemd/sd-adapt-shared/gunicode.h \
	shared/systemd/sd-adapt-shared/idn-util.h \
	shared/systemd/sd-adapt-shared/ioprio.h \
	shared/systemd/sd-adapt-shared/locale-util.h \
	shared/systemd/sd-adapt-shared/memfd-util.h \
	shared/systemd/sd-adapt-shared/missing_fs.h \
	shared/systemd/sd-adapt-shared/missing_keyctl.h \
	shared/systemd/sd-adapt-shared/missing_magic.h \
	shared/systemd/sd-adapt-shared/missing_network.h \
	shared/systemd/sd-adapt-shared/missing_sched.h \
	shared/systemd/sd-adapt-shared/missing_timerfd.h \
	shared/systemd/sd-adapt-shared/mkdir.h \
	shared/systemd/sd-adapt-shared/namespace-util.h \
	shared/systemd/sd-adapt-shared/nm-sd-adapt-shared.h \
	shared/systemd/sd-adapt-shared/nulstr-util.h \
	shared/systemd/sd-adapt-shared/raw-clone.h \
	shared/systemd/sd-adapt-shared/rlimit-util.h \
	shared/systemd/sd-adapt-shared/terminal-util.h \
	shared/systemd/sd-adapt-shared/unaligned.h \
	shared/systemd/sd-adapt-shared/user-util.h \
	shared/systemd/sd-adapt-shared/virt.h \
	shared/systemd/src/basic/alloc-util.c \
	shared/systemd/src/basic/alloc-util.h \
	shared/systemd/src/basic/async.h \
	shared/systemd/src/basic/cgroup-util.h \
	shared/systemd/src/basic/env-file.c \
	shared/systemd/src/basic/env-file.h \
	shared/systemd/src/basic/env-util.c \
	shared/systemd/src/basic/env-util.h \
	shared/systemd/src/basic/errno-util.h \
	shared/systemd/src/basic/escape.c \
	shared/systemd/src/basic/escape.h \
	shared/systemd/src/basic/ether-addr-util.c \
	shared/systemd/src/basic/ether-addr-util.h \
	shared/systemd/src/basic/extract-word.c \
	shared/systemd/src/basic/extract-word.h \
	shared/systemd/src/basic/fd-util.c \
	shared/systemd/src/basic/fd-util.h \
	shared/systemd/src/basic/fileio.c \
	shared/systemd/src/basic/fileio.h \
	shared/systemd/src/basic/format-util.c \
	shared/systemd/src/basic/format-util.h \
	shared/systemd/src/basic/fs-util.c \
	shared/systemd/src/basic/fs-util.h \
	shared/systemd/src/basic/hash-funcs.c \
	shared/systemd/src/basic/hash-funcs.h \
	shared/systemd/src/basic/hashmap.c \
	shared/systemd/src/basic/hashmap.h \
	shared/systemd/src/basic/hexdecoct.c \
	shared/systemd/src/basic/hexdecoct.h \
	shared/systemd/src/basic/hostname-util.c \
	shared/systemd/src/basic/hostname-util.h \
	shared/systemd/src/basic/in-addr-util.c \
	shared/systemd/src/basic/in-addr-util.h \
	shared/systemd/src/basic/io-util.c \
	shared/systemd/src/basic/io-util.h \
	shared/systemd/src/basic/list.h \
	shared/systemd/src/basic/log.h \
	shared/systemd/src/basic/macro.h \
	shared/systemd/src/basic/memory-util.c \
	shared/systemd/src/basic/memory-util.h \
	shared/systemd/src/basic/mempool.c \
	shared/systemd/src/basic/mempool.h \
	shared/systemd/src/basic/missing_fcntl.h \
	shared/systemd/src/basic/missing_random.h \
	shared/systemd/src/basic/missing_socket.h \
	shared/systemd/src/basic/missing_stat.h \
	shared/systemd/src/basic/missing_syscall.h \
	shared/systemd/src/basic/missing_type.h \
	shared/systemd/src/basic/parse-util.c \
	shared/systemd/src/basic/parse-util.h \
	shared/systemd/src/basic/path-util.c \
	shared/systemd/src/basic/path-util.h \
	shared/systemd/src/basic/prioq.c \
	shared/systemd/src/basic/prioq.h \
	shared/systemd/src/basic/process-util.c \
	shared/systemd/src/basic/process-util.h \
	shared/systemd/src/basic/random-util.c \
	shared/systemd/src/basic/random-util.h \
	shared/systemd/src/basic/ratelimit.c \
	shared/systemd/src/basic/ratelimit.h \
	shared/systemd/src/basic/set.h \
	shared/systemd/src/basic/signal-util.c \
	shared/systemd/src/basic/signal-util.h \
	shared/systemd/src/basic/siphash24.h \
	shared/systemd/src/basic/socket-util.c \
	shared/systemd/src/basic/socket-util.h \
	shared/systemd/src/basic/sort-util.h \
	shared/systemd/src/basic/sparse-endian.h \
	shared/systemd/src/basic/stat-util.c \
	shared/systemd/src/basic/stat-util.h \
	shared/systemd/src/basic/stdio-util.h \
	shared/systemd/src/basic/string-table.c \
	shared/systemd/src/basic/string-table.h \
	shared/systemd/src/basic/string-util.c \
	shared/systemd/src/basic/string-util.h \
	shared/systemd/src/basic/strv.c \
	shared/systemd/src/basic/strv.h \
	shared/systemd/src/basic/strxcpyx.c \
	shared/systemd/src/basic/strxcpyx.h \
	shared/systemd/src/basic/time-util.c \
	shared/systemd/src/basic/time-util.h \
	shared/systemd/src/basic/tmpfile-util.c \
	shared/systemd/src/basic/tmpfile-util.h \
	shared/systemd/src/basic/umask-util.h \
	shared/systemd/src/basic/utf8.c \
	shared/systemd/src/basic/utf8.h \
	shared/systemd/src/basic/util.c \
	shared/systemd/src/basic/util.h \
	shared/systemd/src/shared/dns-domain.c \
	shared/systemd/src/shared/dns-domain.h \
	shared/systemd/src/shared/log-link.h \
	shared/systemd/src/shared/web-util.c \
	shared/systemd/src/shared/web-util.h \
	$(NULL)

shared_systemd_libnm_systemd_shared_la_LIBADD = \
	$(GLIB_LIBS) \
	$(CODE_COVERAGE_LDFLAGS) \
	$(NULL)

###############################################################################

src_core_libnm_systemd_core_la_cppflags = \
	$(libsystemd_cppflags) \
	-I$(srcdir)/libnm-core \
	-I$(builddir)/libnm-core \
	-I$(srcdir)/src/core \
	-I$(srcdir)/src/core/systemd/sd-adapt-core \
	-I$(srcdir)/src/core/systemd/src/systemd \
	-I$(srcdir)/src/core/systemd/src/libsystemd-network \
	-I$(srcdir)/src/core/systemd/src/libsystemd/sd-event \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_SYSTEMD \
	$(NULL)

src_core_libnm_systemd_core_la_libadd = \
	$(GLIB_LIBS) \
	$(CODE_COVERAGE_LDFLAGS) \
	$(NULL)

src_core_libnm_systemd_core_la_SOURCES = \
	src/core/systemd/nm-sd-utils-core.c \
	src/core/systemd/nm-sd-utils-core.h \
	src/core/systemd/nm-sd.c \
	src/core/systemd/nm-sd.h \
	src/core/systemd/nm-sd-utils-dhcp.h \
	src/core/systemd/nm-sd-utils-dhcp.c \
	src/core/systemd/sd-adapt-core/condition.h \
	src/core/systemd/sd-adapt-core/conf-parser.h \
	src/core/systemd/sd-adapt-core/device-util.h \
	src/core/systemd/sd-adapt-core/khash.h \
	src/core/systemd/sd-adapt-core/network-util.h \
	src/core/systemd/sd-adapt-core/nm-sd-adapt-core.c \
	src/core/systemd/sd-adapt-core/nm-sd-adapt-core.h \
	src/core/systemd/sd-adapt-core/sd-daemon.h \
	src/core/systemd/sd-adapt-core/sd-device.h \
	src/core/systemd/sd-adapt-core/udev-util.h \
	src/core/systemd/src/libsystemd-network/arp-util.c \
	src/core/systemd/src/libsystemd-network/arp-util.h \
	src/core/systemd/src/libsystemd-network/dhcp-identifier.c \
	src/core/systemd/src/libsystemd-network/dhcp-identifier.h \
	src/core/systemd/src/libsystemd-network/dhcp-internal.h \
	src/core/systemd/src/libsystemd-network/dhcp-lease-internal.h \
	src/core/systemd/src/libsystemd-network/dhcp-network.c \
	src/core/systemd/src/libsystemd-network/dhcp-option.c \
	src/core/systemd/src/libsystemd-network/dhcp-packet.c \
	src/core/systemd/src/libsystemd-network/dhcp-protocol.h \
	src/core/systemd/src/libsystemd-network/dhcp6-internal.h \
	src/core/systemd/src/libsystemd-network/dhcp6-lease-internal.h \
	src/core/systemd/src/libsystemd-network/dhcp6-network.c \
	src/core/systemd/src/libsystemd-network/dhcp6-option.c \
	src/core/systemd/src/libsystemd-network/dhcp6-protocol.h \
	src/core/systemd/src/libsystemd-network/lldp-internal.h \
	src/core/systemd/src/libsystemd-network/lldp-neighbor.c \
	src/core/systemd/src/libsystemd-network/lldp-neighbor.h \
	src/core/systemd/src/libsystemd-network/lldp-network.c \
	src/core/systemd/src/libsystemd-network/lldp-network.h \
	src/core/systemd/src/libsystemd-network/network-internal.c \
	src/core/systemd/src/libsystemd-network/network-internal.h \
	src/core/systemd/src/libsystemd-network/sd-dhcp-client.c \
	src/core/systemd/src/libsystemd-network/sd-dhcp-lease.c \
	src/core/systemd/src/libsystemd-network/sd-dhcp6-client.c \
	src/core/systemd/src/libsystemd-network/sd-dhcp6-lease.c \
	src/core/systemd/src/libsystemd-network/sd-ipv4acd.c \
	src/core/systemd/src/libsystemd-network/sd-ipv4ll.c \
	src/core/systemd/src/libsystemd-network/sd-lldp.c \
	src/core/systemd/src/libsystemd/sd-event/event-source.h \
	src/core/systemd/src/libsystemd/sd-event/event-util.c \
	src/core/systemd/src/libsystemd/sd-event/event-util.h \
	src/core/systemd/src/libsystemd/sd-event/sd-event.c \
	src/core/systemd/src/libsystemd/sd-id128/id128-util.c \
	src/core/systemd/src/libsystemd/sd-id128/id128-util.h \
	src/core/systemd/src/libsystemd/sd-id128/sd-id128.c \
	src/core/systemd/src/systemd/_sd-common.h \
	src/core/systemd/src/systemd/sd-dhcp-client.h \
	src/core/systemd/src/systemd/sd-dhcp-lease.h \
	src/core/systemd/src/systemd/sd-dhcp-option.h \
	src/core/systemd/src/systemd/sd-dhcp6-client.h \
	src/core/systemd/src/systemd/sd-dhcp6-lease.h \
	src/core/systemd/src/systemd/sd-dhcp6-option.h \
	src/core/systemd/src/systemd/sd-event.h \
	src/core/systemd/src/systemd/sd-id128.h \
	src/core/systemd/src/systemd/sd-ipv4acd.h \
	src/core/systemd/src/systemd/sd-ipv4ll.h \
	src/core/systemd/src/systemd/sd-lldp.h \
	src/core/systemd/src/systemd/sd-ndisc.h \
	$(NULL)

src_core_libnm_systemd_core_la_CPPFLAGS = $(src_core_libnm_systemd_core_la_cppflags)
src_core_libnm_systemd_core_la_LIBADD = \
	$(GLIB_LIBS) \
	$(CODE_COVERAGE_LDFLAGS) \
	$(NULL)
$(src_core_libnm_systemd_core_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

EXTRA_DIST += \
	src/core/systemd/meson.build

###############################################################################

src_core_libNetworkManagerBase_la_CPPFLAGS = \
	$(libsystemd_cppflags) \
	$(src_core_cppflags)

src_core_libNetworkManagerBase_la_SOURCES = \
	\
	src/core/nm-core-utils.c \
	src/core/nm-core-utils.h \
	\
	src/core/NetworkManagerUtils.c \
	src/core/NetworkManagerUtils.h \
	\
	src/core/platform/nmp-object.c \
	src/core/platform/nmp-object.h \
	src/core/platform/nm-platform.c \
	src/core/platform/nm-platform.h \
	src/core/platform/nm-platform-private.h \
	src/core/platform/nm-linux-platform.c \
	src/core/platform/nm-linux-platform.h \
	src/core/platform/nmp-rules-manager.c \
	src/core/platform/nmp-rules-manager.h \
	src/core/platform/wifi/nm-wifi-utils-nl80211.c \
	src/core/platform/wifi/nm-wifi-utils-nl80211.h \
	src/core/platform/wifi/nm-wifi-utils-private.h \
	src/core/platform/wifi/nm-wifi-utils.c \
	src/core/platform/wifi/nm-wifi-utils.h \
	src/core/platform/wpan/nm-wpan-utils.c \
	src/core/platform/wpan/nm-wpan-utils.h \
	\
	src/core/ndisc/nm-lndp-ndisc.c \
	src/core/ndisc/nm-lndp-ndisc.h \
	src/core/ndisc/nm-ndisc.c \
	src/core/ndisc/nm-ndisc.h \
	src/core/ndisc/nm-ndisc-private.h \
	\
	src/core/nm-dbus-utils.c \
	src/core/nm-dbus-utils.h \
	src/core/nm-dbus-object.c \
	src/core/nm-dbus-object.h \
	src/core/nm-netns.c \
	src/core/nm-netns.h \
	src/core/nm-l3-config-data.c \
	src/core/nm-l3-config-data.h \
	src/core/nm-l3-ipv4ll.c \
	src/core/nm-l3-ipv4ll.h \
	src/core/nm-l3cfg.c \
	src/core/nm-l3cfg.h \
	src/core/nm-ip-config.c \
	src/core/nm-ip-config.h \
	src/core/nm-ip4-config.c \
	src/core/nm-ip4-config.h \
	src/core/nm-ip6-config.c \
	src/core/nm-ip6-config.h \
	\
	src/core/dhcp/nm-dhcp-client.c \
	src/core/dhcp/nm-dhcp-client.h \
	src/core/dhcp/nm-dhcp-client-logging.h \
	src/core/dhcp/nm-dhcp-nettools.c \
	src/core/dhcp/nm-dhcp-utils.c \
	src/core/dhcp/nm-dhcp-utils.h \
	src/core/dhcp/nm-dhcp-options.c \
	src/core/dhcp/nm-dhcp-options.h \
	src/core/dhcp/nm-dhcp-systemd.c \
	src/core/dhcp/nm-dhcp-manager.c \
	src/core/dhcp/nm-dhcp-manager.h \
	\
	src/core/main-utils.c \
	src/core/main-utils.h \
	\
	$(NULL)

if WITH_WEXT
src_core_libNetworkManagerBase_la_SOURCES += \
	src/core/platform/wifi/nm-wifi-utils-wext.c \
	src/core/platform/wifi/nm-wifi-utils-wext.h
endif

src_core_libNetworkManagerBase_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBUDEV_LIBS) \
	$(NULL)

$(src_core_libNetworkManagerBase_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

EXTRA_DIST += \
	src/core/platform/linux/nl802154.h

###############################################################################

src_core_libNetworkManager_la_CPPFLAGS = $(src_core_cppflags)

src_core_libNetworkManager_la_SOURCES = \
	\
	src/core/nm-checkpoint.c \
	src/core/nm-checkpoint.h \
	src/core/nm-checkpoint-manager.c \
	src/core/nm-checkpoint-manager.h \
	\
	src/core/devices/nm-acd-manager.c \
	src/core/devices/nm-acd-manager.h \
	src/core/devices/nm-lldp-listener.c \
	src/core/devices/nm-lldp-listener.h \
	src/core/devices/nm-device.c \
	src/core/devices/nm-device.h \
	src/core/devices/nm-device-ethernet-utils.c \
	src/core/devices/nm-device-ethernet-utils.h \
	src/core/devices/nm-device-factory.c \
	src/core/devices/nm-device-factory.h \
	src/core/devices/nm-device-generic.c \
	src/core/devices/nm-device-generic.h \
	src/core/devices/nm-device-logging.h \
	src/core/devices/nm-device-private.h \
	\
	src/core/devices/nm-device-6lowpan.c \
	src/core/devices/nm-device-6lowpan.h \
	src/core/devices/nm-device-bond.c \
	src/core/devices/nm-device-bond.h \
	src/core/devices/nm-device-bridge.c \
	src/core/devices/nm-device-bridge.h \
	src/core/devices/nm-device-dummy.c \
	src/core/devices/nm-device-dummy.h \
	src/core/devices/nm-device-ethernet.c \
	src/core/devices/nm-device-ethernet.h \
	src/core/devices/nm-device-infiniband.c \
	src/core/devices/nm-device-infiniband.h \
	src/core/devices/nm-device-ip-tunnel.c \
	src/core/devices/nm-device-ip-tunnel.h \
	src/core/devices/nm-device-macsec.c \
	src/core/devices/nm-device-macsec.h \
	src/core/devices/nm-device-macvlan.c \
	src/core/devices/nm-device-macvlan.h \
	src/core/devices/nm-device-ppp.c \
	src/core/devices/nm-device-ppp.h \
	src/core/devices/nm-device-tun.c \
	src/core/devices/nm-device-tun.h \
	src/core/devices/nm-device-veth.c \
	src/core/devices/nm-device-veth.h \
	src/core/devices/nm-device-vlan.c \
	src/core/devices/nm-device-vlan.h \
	src/core/devices/nm-device-vrf.c \
	src/core/devices/nm-device-vrf.h \
	src/core/devices/nm-device-vxlan.c \
	src/core/devices/nm-device-vxlan.h \
	src/core/devices/nm-device-wireguard.c \
	src/core/devices/nm-device-wireguard.h \
	src/core/devices/nm-device-wpan.c \
	src/core/devices/nm-device-wpan.h \
	\
	src/core/dhcp/nm-dhcp-dhcpcanon.c \
	src/core/dhcp/nm-dhcp-dhclient.c \
	src/core/dhcp/nm-dhcp-dhcpcd.c \
	src/core/dhcp/nm-dhcp-helper-api.h \
	src/core/dhcp/nm-dhcp-listener.c \
	src/core/dhcp/nm-dhcp-listener.h \
	src/core/dhcp/nm-dhcp-dhclient-utils.c \
	src/core/dhcp/nm-dhcp-dhclient-utils.h \
	\
	src/core/dns/nm-dns-manager.c \
	src/core/dns/nm-dns-manager.h \
	src/core/dns/nm-dns-plugin.c \
	src/core/dns/nm-dns-plugin.h \
	src/core/dns/nm-dns-dnsmasq.c \
	src/core/dns/nm-dns-dnsmasq.h \
	src/core/dns/nm-dns-systemd-resolved.c \
	src/core/dns/nm-dns-systemd-resolved.h \
	src/core/dns/nm-dns-unbound.c \
	src/core/dns/nm-dns-unbound.h \
	\
	src/core/dnsmasq/nm-dnsmasq-manager.c \
	src/core/dnsmasq/nm-dnsmasq-manager.h \
	src/core/dnsmasq/nm-dnsmasq-utils.c \
	src/core/dnsmasq/nm-dnsmasq-utils.h \
	\
	src/core/ppp/nm-ppp-manager-call.c \
	src/core/ppp/nm-ppp-manager-call.h \
	src/core/ppp/nm-ppp-manager.h \
	src/core/ppp/nm-ppp-status.h \
	\
	src/core/nm-hostname-manager.c \
	src/core/nm-hostname-manager.h \
	\
	src/core/settings/nm-agent-manager.c \
	src/core/settings/nm-agent-manager.h \
	src/core/settings/nm-secret-agent.c \
	src/core/settings/nm-secret-agent.h \
	src/core/settings/nm-settings-connection.c \
	src/core/settings/nm-settings-connection.h \
	src/core/settings/nm-settings-storage.c \
	src/core/settings/nm-settings-storage.h \
	src/core/settings/nm-settings-plugin.c \
	src/core/settings/nm-settings-plugin.h \
	src/core/settings/nm-settings.c \
	src/core/settings/nm-settings.h \
	src/core/settings/nm-settings-utils.c \
	src/core/settings/nm-settings-utils.h \
	\
	src/core/settings/plugins/keyfile/nms-keyfile-storage.c \
	src/core/settings/plugins/keyfile/nms-keyfile-storage.h \
	src/core/settings/plugins/keyfile/nms-keyfile-plugin.c \
	src/core/settings/plugins/keyfile/nms-keyfile-plugin.h \
	src/core/settings/plugins/keyfile/nms-keyfile-reader.c \
	src/core/settings/plugins/keyfile/nms-keyfile-reader.h \
	src/core/settings/plugins/keyfile/nms-keyfile-utils.c \
	src/core/settings/plugins/keyfile/nms-keyfile-utils.h \
	src/core/settings/plugins/keyfile/nms-keyfile-writer.c \
	src/core/settings/plugins/keyfile/nms-keyfile-writer.h \
	\
	src/core/supplicant/nm-supplicant-config.c \
	src/core/supplicant/nm-supplicant-config.h \
	src/core/supplicant/nm-supplicant-interface.c \
	src/core/supplicant/nm-supplicant-interface.h \
	src/core/supplicant/nm-supplicant-manager.c \
	src/core/supplicant/nm-supplicant-manager.h \
	src/core/supplicant/nm-supplicant-settings-verify.c \
	src/core/supplicant/nm-supplicant-settings-verify.h \
	src/core/supplicant/nm-supplicant-types.h \
	\
	src/core/vpn/nm-vpn-connection.c \
	src/core/vpn/nm-vpn-connection.h \
	src/core/vpn/nm-vpn-manager.c \
	src/core/vpn/nm-vpn-manager.h \
	\
	src/core/nm-act-request.c \
	src/core/nm-act-request.h \
	src/core/nm-active-connection.c \
	src/core/nm-active-connection.h \
	src/core/nm-audit-manager.c \
	src/core/nm-audit-manager.h \
	src/core/nm-dbus-manager.c \
	src/core/nm-dbus-manager.h \
	src/core/nm-config.c \
	src/core/nm-config.h \
	src/core/nm-config-data.c \
	src/core/nm-config-data.h \
	src/core/nm-connectivity.c \
	src/core/nm-connectivity.h \
	src/core/nm-dcb.c \
	src/core/nm-dcb.h \
	src/core/nm-dhcp-config.c \
	src/core/nm-dhcp-config.h \
	src/core/nm-dispatcher.c \
	src/core/nm-dispatcher.h \
	src/core/nm-firewall-manager.c \
	src/core/nm-firewall-manager.h \
	src/core/nm-proxy-config.c \
	src/core/nm-proxy-config.h \
	src/core/nm-auth-manager.c \
	src/core/nm-auth-manager.h \
	src/core/nm-auth-utils.c \
	src/core/nm-auth-utils.h \
	src/core/nm-manager.c \
	src/core/nm-manager.h \
	src/core/nm-pacrunner-manager.c \
	src/core/nm-pacrunner-manager.h \
	src/core/nm-policy.c \
	src/core/nm-policy.h \
	src/core/nm-rfkill-manager.c \
	src/core/nm-rfkill-manager.h \
	src/core/nm-session-monitor.h \
	src/core/nm-session-monitor.c \
	src/core/nm-keep-alive.c \
	src/core/nm-keep-alive.h \
	src/core/nm-sleep-monitor.c \
	src/core/nm-sleep-monitor.h \
	src/core/nm-types.h \
	\
	$(NULL)

src_core_libNetworkManager_la_LIBADD = \
	src/core/libNetworkManagerBase.la \
	libnm-core/nm-libnm-core-aux/libnm-libnm-core-aux.la \
	libnm-core/nm-keyfile/libnm-keyfile.la \
	libnm-core/libnm-core.la \
	$(libnm_crypto_lib) \
	libnm-core/nm-libnm-core-intern/libnm-libnm-core-intern.la \
	shared/nm-platform/libnm-platform.la \
	shared/nm-base/libnm-base.la \
	shared/nm-log-core/libnm-log-core.la \
	shared/nm-udev-aux/libnm-udev-aux.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	src/core/libnm-systemd-core.la \
	shared/systemd/libnm-systemd-shared.la \
	shared/libnacd.la \
	shared/libndhcp4.la \
	shared/libcrbtree.la \
	shared/libcsiphash.la \
	$(GLIB_LIBS) \
	$(LIBUDEV_LIBS) \
	$(SYSTEMD_LOGIN_LIBS) \
	$(SYSTEMD_JOURNAL_LIBS) \
	$(LIBNDP_LIBS) \
	$(DL_LIBS) \
	$(SELINUX_LIBS) \
	$(LIBAUDIT_LIBS) \
	$(LIBPSL_LIBS) \
	$(LIBCURL_LIBS) \
	$(NULL)

$(src_core_libNetworkManager_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

###############################################################################

check_ltlibraries += src/core/libNetworkManagerTest.la

src_core_tests_cppflags_fake = $(src_core_cppflags_test) -DSETUP=nm_fake_platform_setup
src_core_tests_cppflags_linux = $(src_core_cppflags_test) -DSETUP=nm_linux_platform_setup

src_core_libNetworkManagerTest_la_CPPFLAGS = $(src_core_cppflags_test)

src_core_libNetworkManagerTest_la_SOURCES = \
	src/core/ndisc/nm-fake-ndisc.c \
	src/core/ndisc/nm-fake-ndisc.h \
	src/core/platform/nm-fake-platform.c \
	src/core/platform/nm-fake-platform.h \
	src/core/platform/tests/test-common.c \
	src/core/platform/tests/test-common.h \
	$(NULL)

src_core_libNetworkManagerTest_la_LIBADD = \
	src/core/libNetworkManager.la \
	$(CODE_COVERAGE_LDFLAGS) \
	$(GLIB_LIBS) \
	$(LIBUDEV_LIBS) \
	$(NULL)

$(src_core_libNetworkManagerTest_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

###############################################################################

noinst_PROGRAMS += src/core/NetworkManager-all-sym

src_core_NetworkManager_all_sym_CPPFLAGS = $(src_core_cppflags)

src_core_NetworkManager_all_sym_SOURCES = \
	src/core/main.c

src_core_NetworkManager_all_sym_LDADD = \
	src/core/libNetworkManager.la \
	$(GLIB_LIBS) \
	$(NULL)

src_core_NetworkManager_all_sym_LDFLAGS = \
	-rdynamic \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

$(src_core_NetworkManager_all_sym_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

src/core/NetworkManager.ver: src/core/NetworkManager-all-sym $(core_plugins)
	$(AM_V_GEN) NM="$(NM)" "$(srcdir)/tools/create-exports-NetworkManager.sh" --called-from-build "$(srcdir)"

CLEANFILES += src/core/NetworkManager.ver

EXTRA_src_core_NetworkManager_DEPENDENCIES = \
	src/core/NetworkManager.ver

src_core_NetworkManager_CPPFLAGS = $(src_core_cppflags)

src_core_NetworkManager_SOURCES = \
	src/core/main.c

src_core_NetworkManager_LDADD = \
	src/core/libNetworkManager.la \
	$(GLIB_LIBS) \
	$(NULL)

src_core_NetworkManager_LDFLAGS = \
	-rdynamic \
	-Wl,--version-script="src/core/NetworkManager.ver" \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

$(src_core_NetworkManager_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

###############################################################################

src_core_nm_iface_helper_CPPFLAGS = $(src_core_cppflags)

src_core_nm_iface_helper_SOURCES = \
	src/core/nm-iface-helper.c

src_core_nm_iface_helper_LDADD = \
	src/core/libNetworkManagerBase.la \
	libnm-core/nm-libnm-core-aux/libnm-libnm-core-aux.la \
	libnm-core/nm-keyfile/libnm-keyfile.la \
	libnm-core/libnm-core.la \
	$(libnm_crypto_lib) \
	libnm-core/nm-libnm-core-intern/libnm-libnm-core-intern.la \
	shared/nm-platform/libnm-platform.la \
	shared/nm-base/libnm-base.la \
	shared/nm-log-core/libnm-log-core.la \
	shared/nm-udev-aux/libnm-udev-aux.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	src/core/libnm-systemd-core.la \
	shared/systemd/libnm-systemd-shared.la \
	shared/libnacd.la \
	shared/libndhcp4.la \
	shared/libcrbtree.la \
	shared/libcsiphash.la \
	$(SYSTEMD_JOURNAL_LIBS) \
	$(GLIB_LIBS) \
	$(LIBUDEV_LIBS) \
	$(LIBNDP_LIBS) \
	$(DL_LIBS) \
	$(NULL)

src_core_nm_iface_helper_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS)

$(src_core_nm_iface_helper_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

###############################################################################

noinst_LTLIBRARIES += src/core/initrd/libnmi-core.la

src_core_initrd_libnmi_core_la_CPPFLAGS = \
	$(src_core_cppflags)

src_core_initrd_libnmi_core_la_SOURCES = \
	src/core/initrd/nm-initrd-generator.h \
	src/core/initrd/nmi-cmdline-reader.c \
	src/core/initrd/nmi-dt-reader.c \
	src/core/initrd/nmi-ibft-reader.c \
	$(NULL)

libexec_PROGRAMS += src/core/initrd/nm-initrd-generator

src_core_initrd_nm_initrd_generator_CPPFLAGS = \
	$(src_core_cppflags)

src_core_initrd_nm_initrd_generator_SOURCES = \
	src/core/initrd/nm-initrd-generator.c

src_core_initrd_nm_initrd_generator_LDADD = \
	src/core/initrd/libnmi-core.la \
	src/core/libNetworkManagerBase.la \
	libnm-core/nm-libnm-core-aux/libnm-libnm-core-aux.la \
	libnm-core/nm-keyfile/libnm-keyfile.la \
	libnm-core/libnm-core.la \
	$(libnm_crypto_lib) \
	libnm-core/nm-libnm-core-intern/libnm-libnm-core-intern.la \
	shared/nm-platform/libnm-platform.la \
	shared/nm-base/libnm-base.la \
	shared/nm-log-core/libnm-log-core.la \
	shared/nm-udev-aux/libnm-udev-aux.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/systemd/libnm-systemd-shared.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libndhcp4.la \
	shared/libcsiphash.la \
	$(SYSTEMD_JOURNAL_LIBS) \
	$(GLIB_LIBS) \
	$(NULL)

src_core_initrd_nm_initrd_generator_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS)

check_programs += src/core/initrd/tests/test-dt-reader

src_core_initrd_tests_test_dt_reader_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION_TEST \
	-DTEST_INITRD_DIR=\"$(abs_srcdir)/src/core/initrd/tests\" \
	$(src_core_cppflags)

src_core_initrd_tests_test_dt_reader_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS)

src_core_initrd_tests_test_dt_reader_LDADD = \
	src/core/initrd/libnmi-core.la \
	src/core/libNetworkManagerTest.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	$(GLIB_LIBS) \
	$(NULL)

check_programs += src/core/initrd/tests/test-ibft-reader

src_core_initrd_tests_test_ibft_reader_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION_TEST \
	-DTEST_INITRD_DIR=\"$(abs_srcdir)/src/core/initrd/tests\" \
	$(src_core_cppflags)

src_core_initrd_tests_test_ibft_reader_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS)

src_core_initrd_tests_test_ibft_reader_LDADD = \
	src/core/initrd/libnmi-core.la \
	src/core/libNetworkManagerTest.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	$(GLIB_LIBS) \
	$(NULL)

EXTRA_DIST += \
	src/core/initrd/meson.build \
	src/core/initrd/tests/meson.build \
	src/core/initrd/tests/sysfs/class/net/eth0/address \
	src/core/initrd/tests/sysfs/class/net/eth2/address \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet0/prefix-len \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet0/hostname \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet0/gateway \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet0/mac \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet0/vlan \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet0/primary-dns \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet0/dhcp \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet0/origin \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet0/secondary-dns \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet0/ip-addr \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet0/subnet-mask \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet0/index \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet0/flags \
	src/core/initrd/tests/sysfs/firmware/ibft/initiator/isns-server \
	src/core/initrd/tests/sysfs/firmware/ibft/initiator/initiator-name \
	src/core/initrd/tests/sysfs/firmware/ibft/initiator/pri-radius-server \
	src/core/initrd/tests/sysfs/firmware/ibft/initiator/slp-server \
	src/core/initrd/tests/sysfs/firmware/ibft/initiator/sec-radius-server \
	src/core/initrd/tests/sysfs/firmware/ibft/initiator/index \
	src/core/initrd/tests/sysfs/firmware/ibft/initiator/flags \
	src/core/initrd/tests/sysfs/firmware/ibft/target0/nic-assoc \
	src/core/initrd/tests/sysfs/firmware/ibft/target0/ip-addr \
	src/core/initrd/tests/sysfs/firmware/ibft/target0/chap-type \
	src/core/initrd/tests/sysfs/firmware/ibft/target0/index \
	src/core/initrd/tests/sysfs/firmware/ibft/target0/lun \
	src/core/initrd/tests/sysfs/firmware/ibft/target0/flags \
	src/core/initrd/tests/sysfs/firmware/ibft/target0/port \
	src/core/initrd/tests/sysfs/firmware/ibft/target2/target-name \
	src/core/initrd/tests/sysfs/firmware/ibft/target2/nic-assoc \
	src/core/initrd/tests/sysfs/firmware/ibft/target2/ip-addr \
	src/core/initrd/tests/sysfs/firmware/ibft/target2/chap-type \
	src/core/initrd/tests/sysfs/firmware/ibft/target2/index \
	src/core/initrd/tests/sysfs/firmware/ibft/target2/lun \
	src/core/initrd/tests/sysfs/firmware/ibft/target2/flags \
	src/core/initrd/tests/sysfs/firmware/ibft/target2/port \
	src/core/initrd/tests/sysfs/firmware/ibft/acpi_header/oem_table_id \
	src/core/initrd/tests/sysfs/firmware/ibft/acpi_header/oem_id \
	src/core/initrd/tests/sysfs/firmware/ibft/acpi_header/signature \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet2/prefix-len \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet2/hostname \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet2/gateway \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet2/mac \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet2/vlan \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet2/primary-dns \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet2/dhcp \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet2/origin \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet2/secondary-dns \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet2/ip-addr \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet2/subnet-mask \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet2/index \
	src/core/initrd/tests/sysfs/firmware/ibft/ethernet2/flags \
	src/core/initrd/tests/sysfs-bad-dns1/class/net/eth0/address \
	src/core/initrd/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/prefix-len \
	src/core/initrd/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/gateway \
	src/core/initrd/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/mac \
	src/core/initrd/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/vlan \
	src/core/initrd/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/primary-dns \
	src/core/initrd/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/origin \
	src/core/initrd/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/secondary-dns \
	src/core/initrd/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/ip-addr \
	src/core/initrd/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/subnet-mask \
	src/core/initrd/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/index \
	src/core/initrd/tests/sysfs-bad-dns1/firmware/ibft/initiator/initiator-name \
	src/core/initrd/tests/sysfs-bad-dns1/firmware/ibft/target0/target-name \
	src/core/initrd/tests/sysfs-bad-dns1/firmware/ibft/target0/ip-addr \
	src/core/initrd/tests/sysfs-bad-dns1/firmware/ibft/target0/index \
	src/core/initrd/tests/sysfs-bad-dns1/firmware/ibft/target0/lun \
	src/core/initrd/tests/sysfs-bad-dns1/firmware/ibft/target0/port \
	src/core/initrd/tests/sysfs-bad-dns2/class/net/eth0/address \
	src/core/initrd/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/prefix-len \
	src/core/initrd/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/gateway \
	src/core/initrd/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/mac \
	src/core/initrd/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/vlan \
	src/core/initrd/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/primary-dns \
	src/core/initrd/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/origin \
	src/core/initrd/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/secondary-dns \
	src/core/initrd/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/ip-addr \
	src/core/initrd/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/subnet-mask \
	src/core/initrd/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/index \
	src/core/initrd/tests/sysfs-bad-dns2/firmware/ibft/initiator/initiator-name \
	src/core/initrd/tests/sysfs-bad-dns2/firmware/ibft/target0/target-name \
	src/core/initrd/tests/sysfs-bad-dns2/firmware/ibft/target0/ip-addr \
	src/core/initrd/tests/sysfs-bad-dns2/firmware/ibft/target0/index \
	src/core/initrd/tests/sysfs-bad-dns2/firmware/ibft/target0/lun \
	src/core/initrd/tests/sysfs-bad-dns2/firmware/ibft/target0/port \
	src/core/initrd/tests/sysfs-bad-gateway/class/net/eth0/address \
	src/core/initrd/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/prefix-len \
	src/core/initrd/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/gateway \
	src/core/initrd/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/mac \
	src/core/initrd/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/vlan \
	src/core/initrd/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/primary-dns \
	src/core/initrd/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/origin \
	src/core/initrd/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/secondary-dns \
	src/core/initrd/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/ip-addr \
	src/core/initrd/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/subnet-mask \
	src/core/initrd/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/index \
	src/core/initrd/tests/sysfs-bad-gateway/firmware/ibft/initiator/initiator-name \
	src/core/initrd/tests/sysfs-bad-gateway/firmware/ibft/target0/target-name \
	src/core/initrd/tests/sysfs-bad-gateway/firmware/ibft/target0/ip-addr \
	src/core/initrd/tests/sysfs-bad-gateway/firmware/ibft/target0/index \
	src/core/initrd/tests/sysfs-bad-gateway/firmware/ibft/target0/lun \
	src/core/initrd/tests/sysfs-bad-gateway/firmware/ibft/target0/port \
	src/core/initrd/tests/sysfs-bad-ipaddr/class/net/eth0/address \
	src/core/initrd/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/prefix-len \
	src/core/initrd/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/gateway \
	src/core/initrd/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/mac \
	src/core/initrd/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/vlan \
	src/core/initrd/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/primary-dns \
	src/core/initrd/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/origin \
	src/core/initrd/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/secondary-dns \
	src/core/initrd/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/ip-addr \
	src/core/initrd/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/subnet-mask \
	src/core/initrd/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/index \
	src/core/initrd/tests/sysfs-bad-ipaddr/firmware/ibft/initiator/initiator-name \
	src/core/initrd/tests/sysfs-bad-ipaddr/firmware/ibft/target0/target-name \
	src/core/initrd/tests/sysfs-bad-ipaddr/firmware/ibft/target0/ip-addr \
	src/core/initrd/tests/sysfs-bad-ipaddr/firmware/ibft/target0/index \
	src/core/initrd/tests/sysfs-bad-ipaddr/firmware/ibft/target0/lun \
	src/core/initrd/tests/sysfs-bad-ipaddr/firmware/ibft/target0/port \
	src/core/initrd/tests/sysfs-dhcp/class/net/eth0/address \
	src/core/initrd/tests/sysfs-dhcp/class/net/eth1/address \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/ethernet0/gateway \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/ethernet0/mac \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/ethernet0/vlan \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/ethernet0/primary-dns \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/ethernet0/origin \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/ethernet0/secondary-dns \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/ethernet0/index \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/initiator/initiator-name \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/target0/target-name \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/target0/ip-addr \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/target0/index \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/target0/lun \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/target0/port \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/ethernet1/gateway \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/ethernet1/mac \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/ethernet1/vlan \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/ethernet1/primary-dns \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/ethernet1/origin \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/ethernet1/secondary-dns \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/ethernet1/index \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/target1/target-name \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/target1/ip-addr \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/target1/index \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/target1/lun \
	src/core/initrd/tests/sysfs-dhcp/firmware/ibft/target1/port \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/chosen/bootpath \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/chosen/bootp-request \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/chosen/bootp-response \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/chosen/broadcast-ip \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/chosen/client-ip \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/chosen/client-name \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/chosen/domain-name \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/chosen/gateway-ip \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/chosen/name \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/chosen/netmask-ip \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/chosen/root-path \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/chosen/server-ip \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/chosen/tftp-file \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/chosen/vendor-options \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/ethernet/device_type \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/ethernet/local-mac-address \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/ethernet/mac-address \
	src/core/initrd/tests/sysfs-dt/firmware/devicetree/base/ethernet/name \
	src/core/initrd/tests/sysfs-dt-tftp/firmware/devicetree/base/chosen/bootpath \
	src/core/initrd/tests/sysfs-static/class/net/eth0/address \
	src/core/initrd/tests/sysfs-static/class/net/eth1/address \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet0/prefix-len \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet0/gateway \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet0/mac \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet0/vlan \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet0/primary-dns \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet0/origin \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet0/secondary-dns \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet0/ip-addr \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet0/subnet-mask \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet0/index \
	src/core/initrd/tests/sysfs-static/firmware/ibft/initiator/initiator-name \
	src/core/initrd/tests/sysfs-static/firmware/ibft/target0/target-name \
	src/core/initrd/tests/sysfs-static/firmware/ibft/target0/ip-addr \
	src/core/initrd/tests/sysfs-static/firmware/ibft/target0/index \
	src/core/initrd/tests/sysfs-static/firmware/ibft/target0/lun \
	src/core/initrd/tests/sysfs-static/firmware/ibft/target0/port \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet1/gateway \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet1/mac \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet1/vlan \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet1/primary-dns \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet1/origin \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet1/secondary-dns \
	src/core/initrd/tests/sysfs-static/firmware/ibft/ethernet1/index \
	src/core/initrd/tests/sysfs-static/firmware/ibft/target1/target-name \
	src/core/initrd/tests/sysfs-static/firmware/ibft/target1/ip-addr \
	src/core/initrd/tests/sysfs-static/firmware/ibft/target1/index \
	src/core/initrd/tests/sysfs-static/firmware/ibft/target1/lun \
	src/core/initrd/tests/sysfs-static/firmware/ibft/target1/port \
	src/core/initrd/tests/sysfs-vlan/class/net/eth0/address \
	src/core/initrd/tests/sysfs-vlan/firmware/ibft/ethernet0/prefix-len \
	src/core/initrd/tests/sysfs-vlan/firmware/ibft/ethernet0/mac \
	src/core/initrd/tests/sysfs-vlan/firmware/ibft/ethernet0/vlan \
	src/core/initrd/tests/sysfs-vlan/firmware/ibft/ethernet0/origin \
	src/core/initrd/tests/sysfs-vlan/firmware/ibft/ethernet0/ip-addr \
	src/core/initrd/tests/sysfs-vlan/firmware/ibft/ethernet0/subnet-mask \
	src/core/initrd/tests/sysfs-vlan/firmware/ibft/ethernet0/index \
	src/core/initrd/tests/sysfs-vlan/firmware/ibft/initiator/initiator-name \
	src/core/initrd/tests/sysfs-vlan/firmware/ibft/target0/target-name \
	src/core/initrd/tests/sysfs-vlan/firmware/ibft/target0/ip-addr \
	src/core/initrd/tests/sysfs-vlan/firmware/ibft/target0/index \
	src/core/initrd/tests/sysfs-vlan/firmware/ibft/target0/lun \
	src/core/initrd/tests/sysfs-vlan/firmware/ibft/target0/port \
	$(NULL)

check_programs += src/core/initrd/tests/test-cmdline-reader

src_core_initrd_tests_test_cmdline_reader_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION_TEST \
	-DTEST_INITRD_DIR=\"$(abs_srcdir)/src/core/initrd/tests\" \
	$(src_core_cppflags)

src_core_initrd_tests_test_cmdline_reader_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS)

src_core_initrd_tests_test_cmdline_reader_LDADD = \
	src/core/initrd/libnmi-core.la \
	src/core/libNetworkManagerTest.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	$(GLIB_LIBS) \
	$(NULL)

$(src_core_initrd_libnmi_core_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(src_core_initrd_nm_initrd_generator_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(src_core_initrd_tests_test_cmdline_reader_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(src_core_initrd_tests_test_ibft_reader_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(src_core_initrd_tests_test_dt_reader_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

###############################################################################

EXTRA_DIST += \
	src/core/org.freedesktop.NetworkManager.conf \
	src/core/nm-test-utils-core.h \
	src/core/meson.build

###############################################################################
# src/core/dhcp
###############################################################################

libexec_PROGRAMS += src/core/dhcp/nm-dhcp-helper

src_core_dhcp_nm_dhcp_helper_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	-I$(builddir)/shared \
	-DG_LOG_DOMAIN=\""nm-dhcp-helper"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_GLIB \
	$(GLIB_CFLAGS) \
	$(NULL)

src_core_dhcp_nm_dhcp_helper_SOURCES = \
	src/core/dhcp/nm-dhcp-helper.c \
	src/core/dhcp/nm-dhcp-helper-api.h \
	$(NULL)

src_core_dhcp_nm_dhcp_helper_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver"

src_core_dhcp_nm_dhcp_helper_LDADD = $(GLIB_LIBS)

EXTRA_DIST += \
	src/core/dhcp/meson.build

###############################################################################
# src/core/dhcp/tests
###############################################################################

src_core_dhcp_tests_cppflags = $(src_core_cppflags_test)

src_core_dhcp_tests_ldadd = \
	src/core/libNetworkManagerTest.la

check_programs += \
	src/core/dhcp/tests/test-dhcp-dhclient \
	src/core/dhcp/tests/test-dhcp-utils

src_core_dhcp_tests_test_dhcp_dhclient_CPPFLAGS = $(src_core_dhcp_tests_cppflags)
src_core_dhcp_tests_test_dhcp_utils_CPPFLAGS = $(src_core_dhcp_tests_cppflags)

src_core_dhcp_tests_test_dhcp_dhclient_LDADD = $(src_core_dhcp_tests_ldadd)
src_core_dhcp_tests_test_dhcp_utils_LDADD = $(src_core_dhcp_tests_ldadd)

src_core_dhcp_tests_test_dhcp_dhclient_LDFLAGS = $(src_core_tests_ldflags)
src_core_dhcp_tests_test_dhcp_utils_LDFLAGS = $(src_core_tests_ldflags)

$(src_core_dhcp_tests_test_dhcp_dhclient_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(src_core_dhcp_tests_test_dhcp_utils_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

EXTRA_DIST += \
	src/core/dhcp/tests/test-dhclient-duid.leases \
	src/core/dhcp/tests/test-dhclient-commented-duid.leases \
	src/core/dhcp/tests/meson.build

###############################################################################
# src/core/ppp
###############################################################################

if WITH_PPP

core_plugins += src/core/ppp/libnm-ppp-plugin.la

pppd_plugin_LTLIBRARIES += src/core/ppp/nm-pppd-plugin.la

src_core_ppp_nm_pppd_plugin_la_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	-I$(builddir)/shared \
	-I$(srcdir)/libnm-core \
	-DG_LOG_DOMAIN=\""nm-pppd-plugin"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_GLIB \
	$(GLIB_CFLAGS)

src_core_ppp_nm_pppd_plugin_la_SOURCES = \
	src/core/ppp/nm-pppd-plugin.c \
	src/core/ppp/nm-pppd-plugin.h \
	src/core/ppp/nm-ppp-status.h

src_core_ppp_nm_pppd_plugin_la_LDFLAGS = \
	-module -avoid-version

src_core_ppp_nm_pppd_plugin_la_LIBADD = \
	$(GLIB_LIBS) \
	$(DL_LIBS) \
	$(NULL)

$(src_core_ppp_nm_pppd_plugin_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

src_core_ppp_libnm_ppp_plugin_la_SOURCES = \
	src/core/ppp/nm-pppd-plugin.h \
	src/core/ppp/nm-ppp-manager.c \
	src/core/ppp/nm-ppp-manager.h \
	src/core/ppp/nm-ppp-plugin-api.h \
	src/core/ppp/nm-ppp-status.h \
	$(NULL)

EXTRA_src_core_ppp_libnm_ppp_plugin_la_DEPENDENCIES = \
	src/core/ppp/nm-ppp-plugin.ver \
	$(NULL)

src_core_ppp_libnm_ppp_plugin_la_CPPFLAGS = $(src_core_cppflags_base)

src_core_ppp_libnm_ppp_plugin_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script="$(srcdir)/src/core/ppp/nm-ppp-plugin.ver" \
	$(NULL)

src_core_ppp_libnm_ppp_plugin_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

$(src_core_ppp_libnm_ppp_plugin_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

endif

EXTRA_DIST += \
	src/core/ppp/meson.build

###############################################################################
# src/core/settings/plugins/keyfile/tests
###############################################################################

check_programs += src/core/settings/plugins/keyfile/tests/test-keyfile-settings

src_core_settings_plugins_keyfile_tests_test_keyfile_settings_CPPFLAGS = $(src_core_cppflags_test)

src_core_settings_plugins_keyfile_tests_test_keyfile_settings_LDFLAGS = \
	$(GLIB_LIBS) \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS)

src_core_settings_plugins_keyfile_tests_test_keyfile_settings_LDADD = \
	src/core/libNetworkManagerTest.la

$(src_core_settings_plugins_keyfile_tests_test_keyfile_settings_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

EXTRA_DIST += \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Wired_Connection \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_GSM_Connection \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Wireless_Connection \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Wired_Connection_MAC_Case \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_MAC_Old_Format \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_MAC_IB_Old_Format \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Wired_Connection_IP6 \
	src/core/settings/plugins/keyfile/tests/keyfiles/ATT_Data_Connect_BT \
	src/core/settings/plugins/keyfile/tests/keyfiles/ATT_Data_Connect_Plain \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_String_SSID \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Intlist_SSID \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Intlike_SSID \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Intlike_SSID_2 \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Wired_TLS_Old \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Wired_TLS_New \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Wired_TLS_Blob \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Wired_TLS_Path_Missing \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_InfiniBand_Connection \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Bridge_Main \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Bridge_Component \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_New_Wired_Group_Name \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_New_Wireless_Group_Names \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_minimal_1 \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_minimal_2 \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_minimal_slave_1 \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_minimal_slave_2 \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_minimal_slave_3 \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_minimal_slave_4 \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Missing_Vlan_Setting \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Missing_Vlan_Flags \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Missing_ID_UUID \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Enum_Property \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_Flags_Property \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_dcb_connection \
	src/core/settings/plugins/keyfile/tests/keyfiles/Test_TC_Config \
	\
	src/core/settings/plugins/keyfile/tests/keyfiles/test-ca-cert.pem \
	src/core/settings/plugins/keyfile/tests/keyfiles/test-key-and-cert.pem \
	\
	src/core/settings/plugins/keyfile/tests/meson.build

###############################################################################
# src/core/settings/plugins/ifcfg-rh
###############################################################################

if CONFIG_PLUGIN_IFCFG_RH

core_plugins += src/core/settings/plugins/ifcfg-rh/libnm-settings-plugin-ifcfg-rh.la

noinst_LTLIBRARIES += \
	src/core/settings/plugins/ifcfg-rh/libnmdbus-ifcfg-rh.la \
	src/core/settings/plugins/ifcfg-rh/libnms-ifcfg-rh-core.la

###############################################################################

nodist_src_core_settings_plugins_ifcfg_rh_libnmdbus_ifcfg_rh_la_SOURCES = \
	src/core/settings/plugins/ifcfg-rh/nmdbus-ifcfg-rh.c \
	src/core/settings/plugins/ifcfg-rh/nmdbus-ifcfg-rh.h

src_core_settings_plugins_ifcfg_rh_libnmdbus_ifcfg_rh_la_CPPFLAGS = \
	$(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(src_core_cppflags_base)) \
	$(INTROSPECTION_EXTRA_CFLAGS) \
	$(NULL)

CLEANFILES += $(nodist_src_core_settings_plugins_ifcfg_rh_libnmdbus_ifcfg_rh_la_SOURCES)

src/core/settings/plugins/ifcfg-rh/nmdbus-ifcfg-rh.h: src/core/settings/plugins/ifcfg-rh/nm-ifcfg-rh.xml
	@$(MKDIR_P) src/core/settings/plugins/ifcfg-rh/
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--c-namespace NMDBus \
		--interface-prefix com.redhat \
		$<

src/core/settings/plugins/ifcfg-rh/nmdbus-ifcfg-rh.c: src/core/settings/plugins/ifcfg-rh/nmdbus-ifcfg-rh.h
	@true

###############################################################################

src_core_settings_plugins_ifcfg_rh_libnms_ifcfg_rh_core_la_SOURCES = \
	src/core/settings/plugins/ifcfg-rh/nms-ifcfg-rh-common.h \
	src/core/settings/plugins/ifcfg-rh/shvar.c \
	src/core/settings/plugins/ifcfg-rh/shvar.h \
	src/core/settings/plugins/ifcfg-rh/nms-ifcfg-rh-utils.c \
	src/core/settings/plugins/ifcfg-rh/nms-ifcfg-rh-utils.h \
	src/core/settings/plugins/ifcfg-rh/nms-ifcfg-rh-reader.c \
	src/core/settings/plugins/ifcfg-rh/nms-ifcfg-rh-reader.h \
	src/core/settings/plugins/ifcfg-rh/nms-ifcfg-rh-writer.c \
	src/core/settings/plugins/ifcfg-rh/nms-ifcfg-rh-writer.h \
	$(NULL)

src_core_settings_plugins_ifcfg_rh_libnms_ifcfg_rh_core_la_CPPFLAGS = $(src_core_cppflags_base)

$(src_core_settings_plugins_ifcfg_rh_libnms_ifcfg_rh_core_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

###############################################################################

src_core_settings_plugins_ifcfg_rh_libnm_settings_plugin_ifcfg_rh_la_SOURCES = \
	src/core/settings/plugins/ifcfg-rh/nms-ifcfg-rh-storage.c \
	src/core/settings/plugins/ifcfg-rh/nms-ifcfg-rh-storage.h \
	src/core/settings/plugins/ifcfg-rh/nms-ifcfg-rh-plugin.c \
	src/core/settings/plugins/ifcfg-rh/nms-ifcfg-rh-plugin.h \
	$(NULL)

src_core_settings_plugins_ifcfg_rh_libnm_settings_plugin_ifcfg_rh_la_CPPFLAGS = $(src_core_cppflags_base)

src_core_settings_plugins_ifcfg_rh_libnm_settings_plugin_ifcfg_rh_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script="$(srcdir)/linker-script-settings.ver" \
	$(SANITIZER_EXEC_LDFLAGS)

src_core_settings_plugins_ifcfg_rh_libnm_settings_plugin_ifcfg_rh_la_LIBADD = \
	src/core/settings/plugins/ifcfg-rh/libnms-ifcfg-rh-core.la

$(src_core_settings_plugins_ifcfg_rh_libnm_settings_plugin_ifcfg_rh_la_OBJECTS): src/core/settings/plugins/ifcfg-rh/nmdbus-ifcfg-rh.h
$(src_core_settings_plugins_ifcfg_rh_libnm_settings_plugin_ifcfg_rh_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

check-local-symbols-settings-ifcfg-rh: src/core/settings/plugins/ifcfg-rh/libnm-settings-plugin-ifcfg-rh.la
	$(call check_so_symbols,$(builddir)/src/core/settings/plugins/ifcfg-rh/.libs/libnm-settings-plugin-ifcfg-rh.so)

check_local += check-local-symbols-settings-ifcfg-rh

###############################################################################
# src/core/settings/plugins/ifcfg-rh/tests
###############################################################################

check_programs += src/core/settings/plugins/ifcfg-rh/tests/test-ifcfg-rh

src_core_settings_plugins_ifcfg_rh_tests_test_ifcfg_rh_SOURCES = \
	src/core/settings/plugins/ifcfg-rh/tests/test-ifcfg-rh.c

src_core_settings_plugins_ifcfg_rh_tests_test_ifcfg_rh_CPPFLAGS = $(src_core_cppflags_base_test)

src_core_settings_plugins_ifcfg_rh_tests_test_ifcfg_rh_LDFLAGS = \
	$(GLIB_LIBS) \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS)

src_core_settings_plugins_ifcfg_rh_tests_test_ifcfg_rh_LDADD = \
	src/core/settings/plugins/ifcfg-rh/libnms-ifcfg-rh-core.la \
	src/core/libNetworkManagerTest.la

$(src_core_settings_plugins_ifcfg_rh_tests_test_ifcfg_rh_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

dist_libexec_SCRIPTS += \
	src/core/settings/plugins/ifcfg-rh/nm-ifup \
	src/core/settings/plugins/ifcfg-rh/nm-ifdown

install-data-hook-ifcfg-rh:
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(sysconfdir)/sysconfig/network-scripts

install_data_hook += install-data-hook-ifcfg-rh

endif

EXTRA_DIST += \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-System_test-bridge-component-a.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-System_test-bridge-component-b.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-System_test-wired-802-1X-subj-matches.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_User_1.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_Bond_Main.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_Bridge_Component.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_Permissions.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_Proxy_Basic.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_Routing_Rules.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_Team_Infiniband_Port.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_Team_Port.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_VLAN_reorder_hdr.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_WiFi_AP_Mode.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_WiFi_Band_A.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_WiFi_Hidden.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_WiFi_MAC_always.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_WiFi_MAC_default.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_WiFi_MAC_missing.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_WiFi_MAC_never.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_Wifi_LEAP.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_Wifi_WEP_104_ASCII.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_Wired_Auto-Negotiate.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_Wired_Static_Routes.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_Wired_Wake-on-LAN.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Test_Write_Wired_match.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-Vlan_test-vlan-interface.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-dcb-test.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-netmask-1 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-netmask-1.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-random_wifi_connection.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-random_wifi_connection_2.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-team-slave-enp31s0f1-142.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-bond-eth-type \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-bond-main \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-bond-mode-numeric \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-bond-slave \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-bond-slave-ib \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-bridge-component \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-bridge-main \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-bridge-missing-stp \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb-bad-booleans \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb-bad-percent \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb-bad-uints \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb-default-app-priorities \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb-pgpct-not-100 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb-short-booleans \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb-short-percent \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dcb-short-uints \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-dns-options \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-fcoe-fabric \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-fcoe-vn2vn \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-ibft \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-infiniband \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-ip6-disabled.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-minimal \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-misc-variables \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-nm-controlled \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-nm-controlled-unrecognized \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-noip \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-onboot-no \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-permissions \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-read-proxy-basic \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-sit-ignore \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-sriov \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-sriov-write.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-static-routes-legacy \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-static-routes-legacy.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-tc \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-tc-write.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-team-master-1 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-team-master-2 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-team-master-invalid \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-team-port-1 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-team-port-2 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-team-port-empty-config \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-unrecognized \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-variables-corner-cases-1 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-flags-1 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-flags-2 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-interface \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-only-device \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-only-vlanid \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-physdev \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-reorder-hdr-1 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-reorder-hdr-2 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-trailing-spaces \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-band-a \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-band-a-channel-mismatch \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-band-bg-channel-mismatch \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-dynamic-wep-leap \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-hidden \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-leap \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-leap-agent \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-leap-always-ask \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-mac-random-always \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-mac-random-default \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-mac-random-missing \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-mac-random-never \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-open \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-open-auto \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-open-ssid-bad-hex \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-open-ssid-hex \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-open-ssid-long-hex \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-open-ssid-long-quoted \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-open-ssid-quoted \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-owe \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-sae \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wep \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wep-104-ascii \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wep-40-ascii \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wep-adhoc \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wep-agent-keys \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wep-eap-ttls-chap \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wep-no-keys \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wep-passphrase \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-eap-tls \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-eap-ttls-tls \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-eap-suite-b-192-tls \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-psk \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-psk-2 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-psk-adhoc \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-psk-hex \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-psk-unquoted \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-psk-unquoted2 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-802-1X-subj-matches \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-802-1x-password-raw \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-802-1x-ttls-eapgtc \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-8021x-peap-mschapv2 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-8021x-tls-agent \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-8021x-tls-always \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-8021x-tls-p12-no-client-cert \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-auto-negotiate-on \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-autoip \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-ctc-static \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-defroute-no \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-defroute-no-gatewaydev-yes \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-dhcp \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-dhcp-plus-ip \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-dhcp-send-hostname \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-dhcp6-only \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-dhcpv6-hostname-fallback \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-global-gateway \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-global-gateway-ignore \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-ipv4-manual-1 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-ipv4-manual-2 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-ipv4-manual-3 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-ipv4-manual-4 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-ipv6-manual \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-ipv6-only \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-ipv6-only-1 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-never-default \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-obsolete-gateway-n \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-qeth-static \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-shared-plus-ip \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-static \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-static-bootproto \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-static-no-prefix-16 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-static-no-prefix-24 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-static-no-prefix-8 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-static-routes \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-static-routes-legacy \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-unknown-ethtool-opt \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wired-wake-on-lan \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-write-unknown-1 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-write-unknown-1.expected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-write-unknown-2 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-write-unknown-2.expected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-write-unknown-3 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-write-unknown-3.expected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-write-unknown-4 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-write-unknown-4.expected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test_write_wired_auto_negotiate_on.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-dynamic-wep-leap \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-leap \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-sae \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wep \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wep-104-ascii \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wep-40-ascii \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wep-adhoc \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wep-eap-ttls-chap \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wep-passphrase \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wpa-eap-tls \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wpa-eap-ttls-tls \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wpa-psk \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wpa-psk-2 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wpa-psk-adhoc \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wpa-psk-hex \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wpa-psk-unquoted \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wifi-wpa-psk-unquoted2 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wired-802-1x-password-raw \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/keys-test-wired-8021x-peap-mschapv2 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/network-test-wired-defroute-no-gatewaydev-yes \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/network-test-wired-global-gateway \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/network-test-wired-global-gateway-ignore \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/network-test-wired-never-default \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/route-test-static-routes-legacy \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/route-test-wired-static-routes \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/route-test-wired-static-routes-legacy \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/route6-test-wired-ipv6-manual \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/test1_key_and_cert.pem \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/test_ca_cert.pem \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/test_client.p12 \
	$(NULL)

# make target dependencies can't have colons in their names, which ends up
# meaning that we can't add the alias files to EXTRA_DIST. They are instead
# dist'ed via dist-hook-settings-ifcfg-rh below.
src_core_settings_plugins_ifcfg_rh_tests_network_scripts_alias_files = \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem0 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem0:1 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem0:2 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem0:99 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem1 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem1:1 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem2 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem2:1 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem3 \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-aliasem3:1

dist-hook-settings-ifcfg-rh-alias-files:
	@for f in $(src_core_settings_plugins_ifcfg_rh_tests_network_scripts_alias_files); do \
		cp $(abs_srcdir)/$$f $(distdir)/src/core/settings/plugins/ifcfg-rh/tests/network-scripts/; \
	done

dist_hook += dist-hook-settings-ifcfg-rh-alias-files

###############################################################################

if CONFIG_PLUGIN_IFCFG_RH
dbusservice_DATA += src/core/settings/plugins/ifcfg-rh/nm-ifcfg-rh.conf
endif

EXTRA_DIST += \
	src/core/settings/plugins/ifcfg-rh/nm-ifcfg-rh.conf \
	src/core/settings/plugins/ifcfg-rh/nm-ifcfg-rh.xml \
	src/core/settings/plugins/ifcfg-rh/meson.build \
	src/core/settings/plugins/ifcfg-rh/tests/meson.build

###############################################################################
# src/core/settings/plugins/ifupdown
###############################################################################

if CONFIG_PLUGIN_IFUPDOWN

core_plugins += src/core/settings/plugins/ifupdown/libnm-settings-plugin-ifupdown.la

noinst_LTLIBRARIES += src/core/settings/plugins/ifupdown/libnms-ifupdown-core.la

src_core_settings_plugins_ifupdown_libnms_ifupdown_core_la_SOURCES = \
	src/core/settings/plugins/ifupdown/nms-ifupdown-interface-parser.c \
	src/core/settings/plugins/ifupdown/nms-ifupdown-interface-parser.h \
	src/core/settings/plugins/ifupdown/nms-ifupdown-parser.c \
	src/core/settings/plugins/ifupdown/nms-ifupdown-parser.h \
	$(NULL)

src_core_settings_plugins_ifupdown_libnms_ifupdown_core_la_CPPFLAGS = $(src_core_cppflags_base)

src_core_settings_plugins_ifupdown_libnms_ifupdown_core_la_LIBADD = \
	$(LIBUDEV_LIBS) \
	$(NULL)

src_core_settings_plugins_ifupdown_libnm_settings_plugin_ifupdown_la_SOURCES = \
	src/core/settings/plugins/ifupdown/nms-ifupdown-plugin.c \
	src/core/settings/plugins/ifupdown/nms-ifupdown-plugin.h \
	$(NULL)

src_core_settings_plugins_ifupdown_libnm_settings_plugin_ifupdown_la_CPPFLAGS = $(src_core_cppflags_base)

src_core_settings_plugins_ifupdown_libnm_settings_plugin_ifupdown_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script="$(srcdir)/linker-script-settings.ver" \
	$(NULL)

src_core_settings_plugins_ifupdown_libnm_settings_plugin_ifupdown_la_LIBADD = \
	src/core/settings/plugins/ifupdown/libnms-ifupdown-core.la \
	$(LIBUDEV_LIBS) \
	$(NULL)

$(src_core_settings_plugins_ifupdown_libnm_settings_plugin_ifupdown_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(src_core_settings_plugins_ifupdown_libnms_ifupdown_core_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

check-local-symbols-settings-ifupdown: src/core/settings/plugins/ifupdown/libnm-settings-plugin-ifupdown.la
	$(call check_so_symbols,$(builddir)/src/core/settings/plugins/ifupdown/.libs/libnm-settings-plugin-ifupdown.so)

check_local += check-local-symbols-settings-ifupdown

###############################################################################

check_programs += src/core/settings/plugins/ifupdown/tests/test-ifupdown

src_core_settings_plugins_ifupdown_tests_test_ifupdown_CPPFLAGS = $(src_core_cppflags_base_test)

src_core_settings_plugins_ifupdown_tests_test_ifupdown_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS)

src_core_settings_plugins_ifupdown_tests_test_ifupdown_LDADD = \
	src/core/settings/plugins/ifupdown/libnms-ifupdown-core.la \
	src/core/libNetworkManagerTest.la \
	$(GLIB_LIBS) \
	$(NULL)

$(src_core_settings_plugins_ifupdown_tests_test_ifupdown_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

endif

EXTRA_DIST += \
	src/core/settings/plugins/ifupdown/tests/test1 \
	src/core/settings/plugins/ifupdown/tests/test2 \
	src/core/settings/plugins/ifupdown/tests/test3 \
	src/core/settings/plugins/ifupdown/tests/test4 \
	src/core/settings/plugins/ifupdown/tests/test5 \
	src/core/settings/plugins/ifupdown/tests/test6 \
	src/core/settings/plugins/ifupdown/tests/test7 \
	src/core/settings/plugins/ifupdown/tests/test8 \
	src/core/settings/plugins/ifupdown/tests/test9 \
	src/core/settings/plugins/ifupdown/tests/test11 \
	src/core/settings/plugins/ifupdown/tests/test12 \
	src/core/settings/plugins/ifupdown/tests/test13 \
	src/core/settings/plugins/ifupdown/tests/test14 \
	src/core/settings/plugins/ifupdown/tests/test15 \
	src/core/settings/plugins/ifupdown/tests/test16 \
	src/core/settings/plugins/ifupdown/tests/test17-wired-static-verify-ip4 \
	src/core/settings/plugins/ifupdown/tests/test18-wired-static-verify-ip6 \
	src/core/settings/plugins/ifupdown/tests/test19-wired-static-verify-ip4-plen \
	src/core/settings/plugins/ifupdown/tests/test20-source-stanza \
	src/core/settings/plugins/ifupdown/tests/test20-source-stanza.eth0 \
	src/core/settings/plugins/ifupdown/tests/test20-source-stanza.eth1 \
	src/core/settings/plugins/ifupdown/tests/test21-source-dir-stanza \
	src/core/settings/plugins/ifupdown/tests/test21-source-dir-stanza.d \
	src/core/settings/plugins/ifupdown/tests/test22-duplicate-stanzas \
	src/core/settings/plugins/ifupdown/meson.build \
	src/core/settings/plugins/ifupdown/tests/meson.build

###############################################################################
# src/core/devices
###############################################################################

EXTRA_DIST += \
	src/core/devices/meson.build

###############################################################################
# src/core/devices/adsl
###############################################################################

core_plugins += src/core/devices/adsl/libnm-device-plugin-adsl.la

src_core_devices_adsl_libnm_device_plugin_adsl_la_SOURCES = \
	src/core/devices/adsl/nm-atm-manager.c \
	src/core/devices/adsl/nm-device-adsl.c \
	src/core/devices/adsl/nm-device-adsl.h

src_core_devices_adsl_libnm_device_plugin_adsl_la_CPPFLAGS = $(src_core_cppflags_device_plugin)

src_core_devices_adsl_libnm_device_plugin_adsl_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script="$(srcdir)/linker-script-devices.ver"

src_core_devices_adsl_libnm_device_plugin_adsl_la_LIBADD = \
	$(LIBUDEV_LIBS)

check-local-devices-adsl: src/core/devices/adsl/libnm-device-plugin-adsl.la
	$(srcdir)/tools/check-exports.sh $(builddir)/src/core/devices/adsl/.libs/libnm-device-plugin-adsl.so "$(srcdir)/linker-script-devices.ver"
	$(call check_so_symbols,$(builddir)/src/core/devices/adsl/.libs/libnm-device-plugin-adsl.so)

check_local += check-local-devices-adsl

EXTRA_DIST += \
	src/core/devices/adsl/meson.build

###############################################################################
# src/core/devices/wwan
###############################################################################

if WITH_MODEM_MANAGER_1

src_core_devices_wwan_cppflags = \
	$(src_core_cppflags_device_plugin) \
	$(MM_GLIB_CFLAGS) \
	$(NULL)

core_plugins += src/core/devices/wwan/libnm-wwan.la

src_core_devices_wwan_libnm_wwan_la_SOURCES = \
	src/core/devices/wwan/nm-modem-broadband.c \
	src/core/devices/wwan/nm-modem-broadband.h \
	src/core/devices/wwan/nm-modem-manager.c \
	src/core/devices/wwan/nm-modem-manager.h \
	src/core/devices/wwan/nm-modem.c \
	src/core/devices/wwan/nm-modem.h \
	src/core/devices/wwan/nm-service-providers.c \
	src/core/devices/wwan/nm-service-providers.h \
	$(NULL)

if WITH_OFONO
src_core_devices_wwan_libnm_wwan_la_SOURCES += \
	src/core/devices/wwan/nm-modem-ofono.c \
	src/core/devices/wwan/nm-modem-ofono.h
endif

src_core_devices_wwan_libnm_wwan_la_CPPFLAGS = $(src_core_devices_wwan_cppflags)

src_core_devices_wwan_libnm_wwan_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/src/core/devices/wwan/libnm-wwan.ver"

src_core_devices_wwan_libnm_wwan_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBSYSTEMD_LIBS) \
	$(MM_GLIB_LIBS)

$(src_core_devices_wwan_libnm_wwan_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

EXTRA_src_core_devices_wwan_libnm_wwan_la_DEPENDENCIES = \
	src/core/devices/wwan/libnm-wwan.ver

core_plugins += src/core/devices/wwan/libnm-device-plugin-wwan.la

src_core_devices_wwan_libnm_device_plugin_wwan_la_SOURCES = \
	src/core/devices/wwan/nm-wwan-factory.c \
	src/core/devices/wwan/nm-device-modem.c \
	src/core/devices/wwan/nm-device-modem.h

src_core_devices_wwan_libnm_device_plugin_wwan_la_CPPFLAGS = $(src_core_devices_wwan_cppflags)

src_core_devices_wwan_libnm_device_plugin_wwan_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script="$(srcdir)/linker-script-devices.ver"

src_core_devices_wwan_libnm_device_plugin_wwan_la_LIBADD = \
	src/core/devices/wwan/libnm-wwan.la \
	$(GLIB_LIBS)

check-local-devices-wwan: src/core/devices/wwan/libnm-device-plugin-wwan.la src/core/devices/wwan/libnm-wwan.la
	$(srcdir)/tools/check-exports.sh $(builddir)/src/core/devices/wwan/.libs/libnm-device-plugin-wwan.so "$(srcdir)/linker-script-devices.ver"
	$(call check_so_symbols,$(builddir)/src/core/devices/wwan/.libs/libnm-device-plugin-wwan.so)
	$(srcdir)/tools/check-exports.sh $(builddir)/src/core/devices/wwan/.libs/libnm-wwan.so "$(srcdir)/src/core/devices/wwan/libnm-wwan.ver"
	$(call check_so_symbols,$(builddir)/src/core/devices/wwan/.libs/libnm-wwan.so)

check_local += check-local-devices-wwan

src_core_devices_wwan_tests_test_service_providers_SOURCES = \
	src/core/devices/wwan/tests/test-service-providers.c \
	src/core/devices/wwan/nm-service-providers.c \
	src/core/devices/wwan/nm-service-providers.h \
	$(NULL)

src_core_devices_wwan_tests_test_service_providers_CPPFLAGS = \
	$(src_core_cppflags_base_test) \
	-I$(srcdir)/src/core/devices/wwan \
	$(NULL)

src_core_devices_wwan_tests_test_service_providers_LDFLAGS = \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_core_devices_wwan_tests_test_service_providers_LDADD = \
	src/core/libNetworkManagerTest.la \
	$(GLIB_LIBS) \
	$(NULL)

check_programs += src/core/devices/wwan/tests/test-service-providers

$(src_core_devices_wwan_tests_test_service_providers_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

endif

EXTRA_DIST += \
	src/core/devices/wwan/libnm-wwan.ver \
	src/core/devices/wwan/meson.build \
	src/core/devices/wwan/tests/test-service-providers.xml \
	$(NULL)

###############################################################################
# src/core/devices/bluetooth
###############################################################################

if WITH_MODEM_MANAGER_1

noinst_LTLIBRARIES += src/core/devices/bluetooth/libnm-bluetooth-utils.la

src_core_devices_bluetooth_libnm_bluetooth_utils_la_SOURCES = \
	src/core/devices/bluetooth/nm-bluez-common.h \
	src/core/devices/bluetooth/nm-bt-error.c \
	src/core/devices/bluetooth/nm-bt-error.h \
	$(NULL)

src_core_devices_bluetooth_libnm_bluetooth_utils_la_CPPFLAGS = \
	$(src_core_cppflags_base) \
	$(NULL)

src_core_devices_bluetooth_libnm_bluetooth_utils_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

if WITH_BLUEZ5_DUN
src_core_devices_bluetooth_libnm_bluetooth_utils_la_SOURCES += \
	src/core/devices/bluetooth/nm-bluez5-dun.c \
	src/core/devices/bluetooth/nm-bluez5-dun.h \
	$(NULL)

src_core_devices_bluetooth_libnm_bluetooth_utils_la_CPPFLAGS += $(BLUEZ5_CFLAGS)
src_core_devices_bluetooth_libnm_bluetooth_utils_la_LIBADD += $(BLUEZ5_LIBS)
endif

$(src_core_devices_bluetooth_libnm_bluetooth_utils_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

###############################################################################

core_plugins += src/core/devices/bluetooth/libnm-device-plugin-bluetooth.la

src_core_devices_bluetooth_libnm_device_plugin_bluetooth_la_SOURCES = \
	src/core/devices/bluetooth/nm-bluez-manager.c \
	src/core/devices/bluetooth/nm-bluez-manager.h \
	src/core/devices/bluetooth/nm-device-bt.c \
	src/core/devices/bluetooth/nm-device-bt.h \
	$(NULL)

src_core_devices_bluetooth_libnm_device_plugin_bluetooth_la_CPPFLAGS = $(src_core_cppflags_device_plugin)

src_core_devices_bluetooth_libnm_device_plugin_bluetooth_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script="$(srcdir)/linker-script-devices.ver"

src_core_devices_bluetooth_libnm_device_plugin_bluetooth_la_LIBADD = \
	src/core/devices/bluetooth/libnm-bluetooth-utils.la \
	src/core/devices/wwan/libnm-wwan.la \
	$(GLIB_LIBS) \
	$(NULL)

###############################################################################

check_programs_norun += \
	src/core/devices/bluetooth/tests/nm-bt-test

src_core_devices_bluetooth_tests_nm_bt_test_CPPFLAGS = \
	$(src_core_cppflags_test) \
	$(NULL)

src_core_devices_bluetooth_tests_nm_bt_test_LDFLAGS = \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_core_devices_bluetooth_tests_nm_bt_test_LDADD = \
	src/core/devices/bluetooth/libnm-bluetooth-utils.la \
	src/core/libNetworkManager.la \
	$(GLIB_LIBS) \
	$(NULL)

$(src_core_devices_bluetooth_tests_nm_bt_test_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

###############################################################################

check-local-devices-bluetooth: src/core/devices/bluetooth/libnm-device-plugin-bluetooth.la
	$(srcdir)/tools/check-exports.sh $(builddir)/src/core/devices/bluetooth/.libs/libnm-device-plugin-bluetooth.so "$(srcdir)/linker-script-devices.ver"
	$(call check_so_symbols,$(builddir)/src/core/devices/bluetooth/.libs/libnm-device-plugin-bluetooth.so)

check_local += check-local-devices-bluetooth

endif

EXTRA_DIST += \
	src/core/devices/bluetooth/meson.build \
	$(NULL)

###############################################################################
# src/core/devices/wifi
###############################################################################

if WITH_WIFI

noinst_LTLIBRARIES += src/core/devices/wifi/libnm-wifi-base.la

src_core_devices_wifi_libnm_wifi_base_la_SOURCES = \
	src/core/devices/wifi/nm-device-olpc-mesh.c \
	src/core/devices/wifi/nm-device-olpc-mesh.h \
	src/core/devices/wifi/nm-device-wifi-p2p.c \
	src/core/devices/wifi/nm-device-wifi-p2p.h \
	src/core/devices/wifi/nm-device-wifi.c \
	src/core/devices/wifi/nm-device-wifi.h \
	src/core/devices/wifi/nm-wifi-ap.c \
	src/core/devices/wifi/nm-wifi-ap.h \
	src/core/devices/wifi/nm-wifi-common.c \
	src/core/devices/wifi/nm-wifi-common.h \
	src/core/devices/wifi/nm-wifi-p2p-peer.c \
	src/core/devices/wifi/nm-wifi-p2p-peer.h \
	src/core/devices/wifi/nm-wifi-utils.c \
	src/core/devices/wifi/nm-wifi-utils.h \
	$(NULL)

if WITH_IWD
src_core_devices_wifi_libnm_wifi_base_la_SOURCES += \
	src/core/devices/wifi/nm-device-iwd.c \
	src/core/devices/wifi/nm-device-iwd.h \
	src/core/devices/wifi/nm-iwd-manager.c \
	src/core/devices/wifi/nm-iwd-manager.h \
	$(NULL)
endif

src_core_devices_wifi_libnm_wifi_base_la_CPPFLAGS = $(src_core_cppflags_device_plugin)

src_core_devices_wifi_libnm_wifi_base_la_LIBADD = \
	$(GLIB_LIBS)

$(src_core_devices_wifi_libnm_wifi_base_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

core_plugins += src/core/devices/wifi/libnm-device-plugin-wifi.la

src_core_devices_wifi_libnm_device_plugin_wifi_la_SOURCES = \
	src/core/devices/wifi/nm-wifi-factory.c \
	$(NULL)

src_core_devices_wifi_libnm_device_plugin_wifi_la_CPPFLAGS = $(src_core_cppflags_device_plugin)

src_core_devices_wifi_libnm_device_plugin_wifi_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script="$(srcdir)/linker-script-devices.ver"

src_core_devices_wifi_libnm_device_plugin_wifi_la_LIBADD = \
	src/core/devices/wifi/libnm-wifi-base.la \
	$(GLIB_LIBS)

check-local-devices-wifi: src/core/devices/wifi/libnm-device-plugin-wifi.la
	$(srcdir)/tools/check-exports.sh $(builddir)/src/core/devices/wifi/.libs/libnm-device-plugin-wifi.so "$(srcdir)/linker-script-devices.ver"
	$(call check_so_symbols,$(builddir)/src/core/devices/wifi/.libs/libnm-device-plugin-wifi.so)

check_local += check-local-devices-wifi

check_programs += src/core/devices/wifi/tests/test-devices-wifi

src_core_devices_wifi_tests_test_devices_wifi_SOURCES = \
	src/core/devices/wifi/tests/test-devices-wifi.c \
	$(NULL)

src_core_devices_wifi_tests_test_devices_wifi_CPPFLAGS = $(src_core_cppflags_base_test)

src_core_devices_wifi_tests_test_devices_wifi_LDADD = \
	src/core/devices/wifi/libnm-wifi-base.la \
	src/core/libNetworkManagerTest.la \
	src/core/libNetworkManagerBase.la \
	$(NULL)

src_core_devices_wifi_tests_test_devices_wifi_LDFLAGS = $(SANITIZER_EXEC_LDFLAGS)

$(src_core_devices_wifi_tests_test_devices_wifi_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

endif

EXTRA_DIST += \
	src/core/devices/wifi/meson.build \
	$(NULL)

###############################################################################
# src/core/devices/team
###############################################################################

if WITH_TEAMDCTL

core_plugins += src/core/devices/team/libnm-device-plugin-team.la

src_core_devices_team_libnm_device_plugin_team_la_SOURCES = \
	src/core/devices/team/nm-team-factory.c \
	src/core/devices/team/nm-device-team.c \
	src/core/devices/team/nm-device-team.h \
	$(NULL)

src_core_devices_team_libnm_device_plugin_team_la_CPPFLAGS = \
	$(src_core_cppflags_device_plugin) \
	$(LIBTEAMDCTL_CFLAGS) \
	$(JANSSON_CFLAGS) \
	$(NULL)

src_core_devices_team_libnm_device_plugin_team_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script="$(srcdir)/linker-script-devices.ver" \
	$(NULL)

src_core_devices_team_libnm_device_plugin_team_la_LIBADD = \
	$(LIBTEAMDCTL_LIBS) \
	$(JANSSON_LIBS) \
	$(GLIB_LIBS) \
	$(NULL)

check-local-devices-team: src/core/devices/team/libnm-device-plugin-team.la
	$(srcdir)/tools/check-exports.sh $(builddir)/src/core/devices/team/.libs/libnm-device-plugin-team.so "$(srcdir)/linker-script-devices.ver"
	$(call check_so_symbols,$(builddir)/src/core/devices/team/.libs/libnm-device-plugin-team.so)

check_local += check-local-devices-team

endif

EXTRA_DIST += \
	src/core/devices/team/meson.build

###############################################################################
# src/core/devices/ovs
###############################################################################

if WITH_OPENVSWITCH

if HAVE_SYSTEMD

systemdnmunitdir = $(systemdsystemunitdir)/NetworkManager.service.d
systemdnmunit_DATA = \
	data/NetworkManager-ovs.conf

endif

core_plugins += src/core/devices/ovs/libnm-device-plugin-ovs.la

src_core_devices_ovs_libnm_device_plugin_ovs_la_SOURCES = \
	src/core/devices/ovs/nm-ovsdb.c \
	src/core/devices/ovs/nm-ovsdb.h \
	src/core/devices/ovs/nm-ovs-factory.c \
	src/core/devices/ovs/nm-device-ovs-interface.c \
	src/core/devices/ovs/nm-device-ovs-interface.h \
	src/core/devices/ovs/nm-device-ovs-port.c \
	src/core/devices/ovs/nm-device-ovs-port.h \
	src/core/devices/ovs/nm-device-ovs-bridge.c \
	src/core/devices/ovs/nm-device-ovs-bridge.h \
	$(NULL)

src_core_devices_ovs_libnm_device_plugin_ovs_la_CPPFLAGS = \
	$(src_core_cppflags_device_plugin) \
	$(JANSSON_CFLAGS) \
	$(NULL)

src_core_devices_ovs_libnm_device_plugin_ovs_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script="$(srcdir)/linker-script-devices.ver" \
	$(NULL)

src_core_devices_ovs_libnm_device_plugin_ovs_la_LIBADD = \
	$(JANSSON_LIBS) \
	$(GLIB_LIBS) \
	$(NULL)

check-local-devices-ovs: src/core/devices/ovs/libnm-device-plugin-ovs.la
	$(srcdir)/tools/check-exports.sh $(builddir)/src/core/devices/ovs/.libs/libnm-device-plugin-ovs.so "$(srcdir)/linker-script-devices.ver"
	$(call check_so_symbols,$(builddir)/src/core/devices/ovs/.libs/libnm-device-plugin-ovs.so)

endif

EXTRA_DIST += \
	data/NetworkManager-ovs.conf \
	src/core/devices/ovs/meson.build

###############################################################################
# src/core/dnsmasq/tests
###############################################################################

check_programs += src/core/dnsmasq/tests/test-dnsmasq-utils

src_core_dnsmasq_tests_test_dnsmasq_utils_CPPFLAGS = $(src_core_cppflags_test)

src_core_dnsmasq_tests_test_dnsmasq_utils_LDADD = \
	src/core/libNetworkManagerTest.la

src_core_dnsmasq_tests_test_dnsmasq_utils_LDFLAGS = \
	$(SANITIZER_EXEC_LDFLAGS)

$(src_core_dnsmasq_tests_test_dnsmasq_utils_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

EXTRA_DIST += \
	src/core/dnsmasq/tests/meson.build

###############################################################################
# src/core/platform/tests
###############################################################################

src_core_platform_tests_ldflags = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS)

src_core_platform_tests_libadd = \
	src/core/libNetworkManagerTest.la \
	$(GLIB_LIBS) \
	$(LIBUDEV_LIBS)

check_programs_norun += \
	src/core/platform/tests/monitor

check_programs += \
	src/core/platform/tests/test-address-fake \
	src/core/platform/tests/test-address-linux \
	src/core/platform/tests/test-cleanup-fake \
	src/core/platform/tests/test-cleanup-linux \
	src/core/platform/tests/test-link-fake \
	src/core/platform/tests/test-link-linux \
	src/core/platform/tests/test-nmp-object \
	src/core/platform/tests/test-platform-general \
	src/core/platform/tests/test-route-fake \
	src/core/platform/tests/test-route-linux \
	src/core/platform/tests/test-tc-fake \
	src/core/platform/tests/test-tc-linux \
	$(NULL)

src_core_platform_tests_monitor_CPPFLAGS = $(src_core_cppflags_test)
src_core_platform_tests_monitor_LDFLAGS = $(src_core_platform_tests_ldflags)
src_core_platform_tests_monitor_LDADD = $(src_core_platform_tests_libadd)

src_core_platform_tests_test_address_fake_SOURCES = src/core/platform/tests/test-address.c
src_core_platform_tests_test_address_fake_CPPFLAGS = $(src_core_tests_cppflags_fake)
src_core_platform_tests_test_address_fake_LDFLAGS = $(src_core_platform_tests_ldflags)
src_core_platform_tests_test_address_fake_LDADD = $(src_core_platform_tests_libadd)

src_core_platform_tests_test_address_linux_SOURCES = src/core/platform/tests/test-address.c
src_core_platform_tests_test_address_linux_CPPFLAGS = $(src_core_tests_cppflags_linux)
src_core_platform_tests_test_address_linux_LDFLAGS = $(src_core_platform_tests_ldflags)
src_core_platform_tests_test_address_linux_LDADD = $(src_core_platform_tests_libadd)

src_core_platform_tests_test_cleanup_fake_SOURCES = src/core/platform/tests/test-cleanup.c
src_core_platform_tests_test_cleanup_fake_CPPFLAGS = $(src_core_tests_cppflags_fake)
src_core_platform_tests_test_cleanup_fake_LDFLAGS = $(src_core_platform_tests_ldflags)
src_core_platform_tests_test_cleanup_fake_LDADD = $(src_core_platform_tests_libadd)

src_core_platform_tests_test_cleanup_linux_SOURCES = src/core/platform/tests/test-cleanup.c
src_core_platform_tests_test_cleanup_linux_CPPFLAGS = $(src_core_tests_cppflags_linux)
src_core_platform_tests_test_cleanup_linux_LDFLAGS = $(src_core_platform_tests_ldflags)
src_core_platform_tests_test_cleanup_linux_LDADD = $(src_core_platform_tests_libadd)

src_core_platform_tests_test_link_fake_SOURCES = src/core/platform/tests/test-link.c
src_core_platform_tests_test_link_fake_CPPFLAGS = $(src_core_tests_cppflags_fake)
src_core_platform_tests_test_link_fake_LDFLAGS = $(src_core_platform_tests_ldflags)
src_core_platform_tests_test_link_fake_LDADD = $(src_core_platform_tests_libadd)

src_core_platform_tests_test_link_linux_SOURCES = src/core/platform/tests/test-link.c
src_core_platform_tests_test_link_linux_CPPFLAGS = $(src_core_tests_cppflags_linux)
src_core_platform_tests_test_link_linux_LDFLAGS = $(src_core_platform_tests_ldflags)
src_core_platform_tests_test_link_linux_LDADD = $(src_core_platform_tests_libadd)

src_core_platform_tests_test_nmp_object_CPPFLAGS = $(src_core_cppflags_test)
src_core_platform_tests_test_nmp_object_LDFLAGS = $(src_core_platform_tests_ldflags)
src_core_platform_tests_test_nmp_object_LDADD = src/core/libNetworkManagerTest.la

src_core_platform_tests_test_platform_general_CPPFLAGS = $(src_core_cppflags_test)
src_core_platform_tests_test_platform_general_LDFLAGS = $(src_core_platform_tests_ldflags)
src_core_platform_tests_test_platform_general_LDADD = src/core/libNetworkManagerTest.la

src_core_platform_tests_test_route_fake_SOURCES = src/core/platform/tests/test-route.c
src_core_platform_tests_test_route_fake_CPPFLAGS = $(src_core_tests_cppflags_fake)
src_core_platform_tests_test_route_fake_LDFLAGS = $(src_core_platform_tests_ldflags)
src_core_platform_tests_test_route_fake_LDADD = $(src_core_platform_tests_libadd)

src_core_platform_tests_test_route_linux_SOURCES = src/core/platform/tests/test-route.c
src_core_platform_tests_test_route_linux_CPPFLAGS = $(src_core_tests_cppflags_linux)
src_core_platform_tests_test_route_linux_LDFLAGS = $(src_core_platform_tests_ldflags)
src_core_platform_tests_test_route_linux_LDADD = $(src_core_platform_tests_libadd)

src_core_platform_tests_test_tc_fake_SOURCES = src/core/platform/tests/test-tc.c
src_core_platform_tests_test_tc_fake_CPPFLAGS = $(src_core_tests_cppflags_fake)
src_core_platform_tests_test_tc_fake_LDFLAGS = $(src_core_platform_tests_ldflags)
src_core_platform_tests_test_tc_fake_LDADD = $(src_core_platform_tests_libadd)

src_core_platform_tests_test_tc_linux_SOURCES = src/core/platform/tests/test-tc.c
src_core_platform_tests_test_tc_linux_CPPFLAGS = $(src_core_tests_cppflags_linux)
src_core_platform_tests_test_tc_linux_LDFLAGS = $(src_core_platform_tests_ldflags)
src_core_platform_tests_test_tc_linux_LDADD = $(src_core_platform_tests_libadd)


$(src_core_platform_tests_monitor_OBJECTS):               $(libnm_core_lib_h_pub_mkenums)
$(src_core_platform_tests_test_address_fake_OBJECTS):     $(libnm_core_lib_h_pub_mkenums)
$(src_core_platform_tests_test_address_linux_OBJECTS):    $(libnm_core_lib_h_pub_mkenums)
$(src_core_platform_tests_test_cleanup_fake_OBJECTS):     $(libnm_core_lib_h_pub_mkenums)
$(src_core_platform_tests_test_cleanup_linux_OBJECTS):    $(libnm_core_lib_h_pub_mkenums)
$(src_core_platform_tests_test_link_fake_OBJECTS):        $(libnm_core_lib_h_pub_mkenums)
$(src_core_platform_tests_test_link_linux_OBJECTS):       $(libnm_core_lib_h_pub_mkenums)
$(src_core_platform_tests_test_nmp_object_OBJECTS):       $(libnm_core_lib_h_pub_mkenums)
$(src_core_platform_tests_test_platform_general_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(src_core_platform_tests_test_route_fake_OBJECTS):       $(libnm_core_lib_h_pub_mkenums)
$(src_core_platform_tests_test_route_linux_OBJECTS):      $(libnm_core_lib_h_pub_mkenums)
$(src_core_platform_tests_test_tc_fake_OBJECTS):          $(libnm_core_lib_h_pub_mkenums)
$(src_core_platform_tests_test_tc_linux_OBJECTS):         $(libnm_core_lib_h_pub_mkenums)

EXTRA_DIST += \
	src/core/platform/tests/meson.build \
	$(NULL)

###############################################################################
# src/core/devices/tests
###############################################################################

src_core_devices_tests_ldflags = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS)

check_programs += \
	src/core/devices/tests/test-lldp \
	src/core/devices/tests/test-acd

src_core_devices_tests_test_lldp_CPPFLAGS = $(src_core_cppflags_test)
src_core_devices_tests_test_lldp_LDFLAGS = $(src_core_devices_tests_ldflags)
src_core_devices_tests_test_lldp_LDADD = \
	src/core/libNetworkManagerTest.la

src_core_devices_tests_test_acd_CPPFLAGS = $(src_core_cppflags_test)
src_core_devices_tests_test_acd_LDFLAGS = $(src_core_devices_tests_ldflags)
src_core_devices_tests_test_acd_LDADD = \
	src/core/libNetworkManagerTest.la

$(src_core_devices_tests_test_lldp_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(src_core_devices_tests_test_acd_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

EXTRA_DIST += \
	src/core/devices/tests/meson.build

###############################################################################
# src/core/ndisc/tests
###############################################################################

src_core_ndisc_tests_ldflags = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS)

src_core_ndisc_tests_ldadd = \
	src/core/libNetworkManagerTest.la \
	$(GLIB_LIBS)

check_programs += src/core/ndisc/tests/test-ndisc-fake
check_programs_norun += src/core/ndisc/tests/test-ndisc-linux

src_core_ndisc_tests_test_ndisc_linux_CPPFLAGS = $(src_core_cppflags_test)
src_core_ndisc_tests_test_ndisc_linux_LDFLAGS = $(src_core_ndisc_tests_ldflags)
src_core_ndisc_tests_test_ndisc_linux_LDADD = $(src_core_ndisc_tests_ldadd)

src_core_ndisc_tests_test_ndisc_fake_CPPFLAGS = $(src_core_cppflags_test)
src_core_ndisc_tests_test_ndisc_fake_LDFLAGS = $(src_core_ndisc_tests_ldflags)
src_core_ndisc_tests_test_ndisc_fake_LDADD = $(src_core_ndisc_tests_ldadd)

$(src_core_ndisc_tests_test_ndisc_linux_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(src_core_ndisc_tests_test_ndisc_fake_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

EXTRA_DIST += \
	src/core/ndisc/tests/meson.build

###############################################################################
# src/core/supplicant/tests
###############################################################################

check_programs += src/core/supplicant/tests/test-supplicant-config

src_core_supplicant_tests_test_supplicant_config_CPPFLAGS = $(src_core_cppflags_test)

src_core_supplicant_tests_test_supplicant_config_LDADD = \
	src/core/libNetworkManagerTest.la

src_core_supplicant_tests_test_supplicant_config_LDFLAGS = \
	$(SANITIZER_EXEC_LDFLAGS)

$(src_core_supplicant_tests_test_supplicant_config_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

EXTRA_DIST += \
	src/core/supplicant/tests/certs/test-ca-cert.pem \
	src/core/supplicant/tests/certs/test-cert.p12 \
	src/core/supplicant/tests/meson.build

###############################################################################
# src/core/tests/config
###############################################################################

check_programs += src/core/tests/config/test-config

src_core_tests_config_test_config_SOURCES = \
	src/core/tests/config/nm-test-device.c \
	src/core/tests/config/nm-test-device.h \
	src/core/tests/config/test-config.c

src_core_tests_config_test_config_CPPFLAGS = $(src_core_cppflags_test)

src_core_tests_config_test_config_LDADD = \
	src/core/libNetworkManagerTest.la

src_core_tests_config_test_config_LDFLAGS = \
	$(SANITIZER_EXEC_LDFLAGS)

$(src_core_tests_config_test_config_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

EXTRA_DIST += \
	src/core/tests/config/NetworkManager.conf \
	src/core/tests/config/NetworkManager-warn.conf \
	src/core/tests/config/NetworkManager.state \
	src/core/tests/config/bad.conf \
	src/core/tests/config/global-dns-invalid.conf \
	src/core/tests/config/conf.d/00-overrides.conf \
	src/core/tests/config/conf.d/10-more.conf \
	src/core/tests/config/conf.d/20-config-enable-1.conf \
	src/core/tests/config/conf.d/90-last.conf \
	src/core/tests/config/meson.build

###############################################################################
# src/core/tests
###############################################################################

src_core_tests_ldflags = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS)

src_core_tests_ldadd = \
	src/core/libNetworkManagerTest.la

check_programs += \
	src/core/tests/test-core \
	src/core/tests/test-core-with-expect \
	src/core/tests/test-dcb \
	src/core/tests/test-ip4-config \
	src/core/tests/test-ip6-config \
	src/core/tests/test-l3cfg \
	src/core/tests/test-systemd \
	src/core/tests/test-utils \
	src/core/tests/test-wired-defname \
	$(NULL)

src_core_tests_test_ip4_config_CPPFLAGS = $(src_core_cppflags_test)
src_core_tests_test_ip4_config_LDFLAGS = $(src_core_tests_ldflags)
src_core_tests_test_ip4_config_LDADD = $(src_core_tests_ldadd)

src_core_tests_test_ip6_config_CPPFLAGS = $(src_core_cppflags_test)
src_core_tests_test_ip6_config_LDFLAGS = $(src_core_tests_ldflags)
src_core_tests_test_ip6_config_LDADD = $(src_core_tests_ldadd)

src_core_tests_test_dcb_CPPFLAGS = $(src_core_cppflags_test)
src_core_tests_test_dcb_LDFLAGS = $(src_core_tests_ldflags)
src_core_tests_test_dcb_LDADD = $(src_core_tests_ldadd)

src_core_tests_test_core_CPPFLAGS = $(src_core_cppflags_test)
src_core_tests_test_core_LDFLAGS = $(src_core_tests_ldflags)
src_core_tests_test_core_LDADD = $(src_core_tests_ldadd)

src_core_tests_test_core_with_expect_CPPFLAGS = $(src_core_cppflags_test)
src_core_tests_test_core_with_expect_LDFLAGS = $(src_core_tests_ldflags)
src_core_tests_test_core_with_expect_LDADD = $(src_core_tests_ldadd)

src_core_tests_test_wired_defname_CPPFLAGS = $(src_core_cppflags_test)
src_core_tests_test_wired_defname_LDFLAGS = $(src_core_tests_ldflags)
src_core_tests_test_wired_defname_LDADD = $(src_core_tests_ldadd)

src_core_tests_test_utils_CPPFLAGS = $(src_core_cppflags_test)
src_core_tests_test_utils_LDFLAGS = $(src_core_tests_ldflags)
src_core_tests_test_utils_LDADD = $(src_core_tests_ldadd)

src_core_tests_test_l3cfg_CPPFLAGS = $(src_core_cppflags_test)
src_core_tests_test_l3cfg_LDFLAGS = $(src_core_devices_tests_ldflags)
src_core_tests_test_l3cfg_LDADD = $(src_core_tests_ldadd)

$(src_core_tests_test_core_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(src_core_tests_test_core_with_expect_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(src_core_tests_test_dcb_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(src_core_tests_test_ip4_config_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(src_core_tests_test_ip6_config_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(src_core_tests_test_l3cfg_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(src_core_tests_test_utils_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(src_core_tests_test_wired_defname_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

src_core_tests_test_systemd_CPPFLAGS = \
	$(src_core_libnm_systemd_core_la_cppflags) \
	-DNETWORKMANAGER_COMPILATION_TEST \
	$(NULL)

src_core_tests_test_systemd_LDFLAGS = \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_core_tests_test_systemd_LDADD = \
	src/core/libnm-systemd-core.la \
	shared/systemd/libnm-systemd-shared.la \
	shared/libcsiphash.la \
	$(GLIB_LIBS) \
	$(CODE_COVERAGE_LDFLAGS) \
	$(NULL)

$(src_core_tests_test_systemd_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

EXTRA_DIST += \
	src/core/tests/test-secret-agent.py \
	src/core/tests/meson.build

###############################################################################
# dispatcher
###############################################################################

dispatcher_nmdbus_dispatcher_sources = \
	dispatcher/nmdbus-dispatcher.h \
	dispatcher/nmdbus-dispatcher.c \
	$(NULL)

dispatcher/nmdbus-dispatcher.h: dispatcher/nm-dispatcher.xml
	@$(MKDIR_P) dispatcher/
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--c-namespace NMDBus \
		--interface-prefix org.freedesktop \
		$<

dispatcher/nmdbus-dispatcher.c: dispatcher/nmdbus-dispatcher.h

CLEANFILES += $(dispatcher_nmdbus_dispatcher_sources)

###############################################################################

libexec_PROGRAMS += dispatcher/nm-dispatcher

noinst_LTLIBRARIES += \
	dispatcher/libnm-dispatcher-core.la

dispatcher_cppflags = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	-I$(builddir)/shared \
	-I$(srcdir)/libnm-core \
	-I$(builddir)/libnm-core \
	-I$(srcdir)/libnm \
	-I$(builddir)/libnm \
	-I$(srcdir)/dispatcher \
	-I$(builddir)/dispatcher \
	$(GLIB_CFLAGS) \
	-DG_LOG_DOMAIN=\""nm-dispatcher"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT \
	$(NULL)

dispatcher_libnm_dispatcher_core_la_SOURCES = \
	dispatcher/nm-dispatcher-utils.c \
	dispatcher/nm-dispatcher-utils.h \
	$(NULL)

dispatcher_libnm_dispatcher_core_la_CPPFLAGS = $(dispatcher_cppflags)

dispatcher_libnm_dispatcher_core_la_LIBADD = \
	libnm/libnm.la \
	$(GLIB_LIBS)

dispatcher_nm_dispatcher_SOURCES = \
	dispatcher/nm-dispatcher.c \
	$(NULL)

dispatcher_nm_dispatcher_CPPFLAGS = $(dispatcher_cppflags)

dispatcher_nm_dispatcher_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

dispatcher_nm_dispatcher_LDADD = \
	dispatcher/libnm-dispatcher-core.la \
	libnm/libnm.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	$(GLIB_LIBS)

dispatcher/org.freedesktop.nm_dispatcher.service: $(srcdir)/dispatcher/org.freedesktop.nm_dispatcher.service.in
	@sed \
	-e 's|@sbindir[@]|$(sbindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g' \
	-e 's|@libexecdir[@]|$(libexecdir)|g' \
	$< >$@

dbusactivation_DATA += dispatcher/org.freedesktop.nm_dispatcher.service
CLEANFILES += dispatcher/org.freedesktop.nm_dispatcher.service

install-data-hook-dispatcher:
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(nmconfdir)/dispatcher.d
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(nmconfdir)/dispatcher.d/pre-down.d
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(nmconfdir)/dispatcher.d/pre-up.d
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(nmconfdir)/dispatcher.d/no-wait.d
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(nmlibdir)/dispatcher.d
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(nmlibdir)/dispatcher.d/pre-down.d
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(nmlibdir)/dispatcher.d/pre-up.d
	$(mkinstalldirs) -m 0755 $(DESTDIR)$(nmlibdir)/dispatcher.d/no-wait.d

install_data_hook += install-data-hook-dispatcher


dbusservice_DATA += dispatcher/nm-dispatcher.conf

EXTRA_DIST += \
	dispatcher/nm-dispatcher.conf \
	dispatcher/org.freedesktop.nm_dispatcher.service.in \
	dispatcher/nm-dispatcher.xml \
	dispatcher/meson.build

###############################################################################
# dispatcher/tests
###############################################################################

check_programs += dispatcher/tests/test-dispatcher-envp

dispatcher_tests_test_dispatcher_envp_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	-I$(builddir)/shared \
	-I$(srcdir)/libnm-core \
	-I$(builddir)/libnm-core \
	-I$(srcdir)/libnm \
	-I$(builddir)/libnm \
	-I$(srcdir)/dispatcher \
	-I$(builddir)/dispatcher \
	-DNETWORKMANAGER_COMPILATION_TEST \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT \
	$(GLIB_CFLAGS) \
	$(SANITIZER_EXEC_CFLAGS) \
	$(INTROSPECTION_EXTRA_CFLAGS) \
	$(NULL)

dispatcher_tests_test_dispatcher_envp_SOURCES = \
	dispatcher/tests/test-dispatcher-envp.c \
	$(NULL)

nodist_dispatcher_tests_test_dispatcher_envp_SOURCES = $(dispatcher_nmdbus_dispatcher_sources)

$(dispatcher_tests_test_dispatcher_envp_OBJECTS): $(dispatcher_nmdbus_dispatcher_sources)

dispatcher_tests_test_dispatcher_envp_LDFLAGS = \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

dispatcher_tests_test_dispatcher_envp_LDADD = \
	dispatcher/libnm-dispatcher-core.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	libnm/libnm.la \
	$(GLIB_LIBS) \
	$(NULL)

$(dispatcher_tests_test_dispatcher_envp_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

EXTRA_DIST += \
	dispatcher/tests/dispatcher-connectivity-full \
	dispatcher/tests/dispatcher-connectivity-unknown \
	dispatcher/tests/dispatcher-down \
	dispatcher/tests/dispatcher-external \
	dispatcher/tests/dispatcher-up \
	dispatcher/tests/dispatcher-vpn-down \
	dispatcher/tests/dispatcher-vpn-up \
	dispatcher/tests/meson.build \
	$(NULL)

###############################################################################
# clients
###############################################################################

bin_PROGRAMS += clients/nm-online

clients_nm_online_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	-I$(builddir)/shared \
	-I$(srcdir)/libnm-core \
	-I$(builddir)/libnm-core \
	-I$(srcdir)/libnm \
	-I$(builddir)/libnm \
	$(GLIB_CFLAGS) \
	-DG_LOG_DOMAIN=\""nm-online"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT \
	$(NULL)

clients_nm_online_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

clients_nm_online_LDADD = \
	libnm/libnm.la \
	libnm/nm-libnm-aux/libnm-libnm-aux.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	$(GLIB_LIBS) \
	$(NULL)

$(clients_nm_online_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(clients_nm_online_OBJECTS): $(libnm_lib_h_pub_mkenums)

EXTRA_DIST += \
	clients/meson.build

###############################################################################
# clients/common
###############################################################################

clients_cppflags = \
	$(dflt_cppflags) \
	-I$(srcdir)/shared \
	-I$(builddir)/shared \
	-I$(srcdir)/libnm-core \
	-I$(builddir)/libnm-core \
	-I$(srcdir)/libnm \
	-I$(builddir)/libnm \
	-I$(srcdir)/clients/common \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT \
	$(GLIB_CFLAGS) \
	$(SANITIZER_EXEC_CFLAGS) \
	$(NULL)

check_ltlibraries += clients/common/libnmc-base.la

clients_common_libnmc_base_la_SOURCES = \
	clients/common/nm-secret-agent-simple.c \
	clients/common/nm-secret-agent-simple.h \
	clients/common/nm-vpn-helpers.c \
	clients/common/nm-vpn-helpers.h \
	clients/common/nm-client-utils.c \
	clients/common/nm-client-utils.h \
	clients/common/nm-polkit-listener.c \
	clients/common/nm-polkit-listener.h \
	$(NULL)

EXTRA_DIST += \
	clients/common/qrcodegen.c \
	clients/common/qrcodegen.h

clients_common_libnmc_base_la_CPPFLAGS = \
	$(clients_cppflags) \
	-DG_LOG_DOMAIN=\""libnmc"\" \
	$(NULL)

clients_common_libnmc_base_la_LIBADD = \
	libnm/libnm.la \
	$(GLIB_LIBS) \
	$(NULL)

$(clients_common_libnmc_base_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(clients_common_libnmc_base_la_OBJECTS): $(libnm_lib_h_pub_mkenums)
$(clients_common_libnmc_base_la_OBJECTS): clients/common/.dirstamp

clients_common_settings_doc_h = clients/common/settings-docs.h
if BUILD_DOCS
$(clients_common_settings_doc_h): clients/common/settings-docs.xsl libnm/nm-settings-docs-gir.xml clients/common/.dirstamp
	$(AM_V_GEN) $(XSLTPROC) --output $@ $< $(word 2,$^)
DISTCLEANFILES += $(clients_common_settings_doc_h)
check-local-settings-docs: $(clients_common_settings_doc_h)
	$(srcdir)/tools/check-compare-generated.sh "$(srcdir)" "$(builddir)" "$(clients_common_settings_doc_h)"
check_local += check-local-settings-docs
else
$(clients_common_settings_doc_h): $(clients_common_settings_doc_h).in clients/common/.dirstamp
	$(AM_V_GEN) cp "$(srcdir)/$(clients_common_settings_doc_h).in" "$(builddir)/$(clients_common_settings_doc_h)"
check-local-settings-docs:
endif
EXTRA_DIST += \
	$(clients_common_settings_doc_h) \
	$(clients_common_settings_doc_h).in

if HAVE_INTROSPECTION
check_ltlibraries += clients/common/libnmc.la
else
EXTRA_LTLIBRARIES += clients/common/libnmc.la
endif

clients_common_libnmc_la_SOURCES = \
	shared/nm-meta-setting.c \
	shared/nm-meta-setting.h \
	\
	clients/common/nm-meta-setting-desc.c \
	clients/common/nm-meta-setting-desc.h \
	clients/common/nm-meta-setting-access.c \
	clients/common/nm-meta-setting-access.h \
	$(NULL)

clients_common_libnmc_la_CPPFLAGS = \
	$(clients_cppflags) \
	-I$(builddir)/clients/common \
	-DG_LOG_DOMAIN=\""libnmc"\" \
	$(NULL)

clients_common_libnmc_la_LIBADD = \
	libnm/libnm.la \
	$(GLIB_LIBS) \
	$(NULL)

$(clients_common_libnmc_la_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(clients_common_libnmc_la_OBJECTS): $(clients_common_settings_doc_h)
$(clients_common_libnmc_la_OBJECTS): clients/common/.dirstamp

if HAVE_INTROSPECTION
check_programs += clients/common/tests/test-clients-common
else
if BUILD_NMCLI
check_programs += clients/common/tests/test-clients-common
endif
endif

clients_common_tests_test_clients_common_CPPFLAGS = \
	-I$(srcdir)/clients/common/tests \
	$(clients_cppflags) \
	-DNETWORKMANAGER_COMPILATION_TEST \
	$(NULL)

clients_common_tests_test_clients_common_LDFLAGS = \
	$(SANITIZER_EXEC_LDFLAGS)

clients_common_tests_test_clients_common_LDADD = \
	clients/common/libnmc.la \
	clients/common/libnmc-base.la \
	libnm-core/nm-libnm-core-aux/libnm-libnm-core-aux.la \
	libnm-core/nm-libnm-core-intern/libnm-libnm-core-intern.la \
	shared/nm-base/libnm-base.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	libnm/libnm.la \
	$(GLIB_LIBS)

$(clients_common_tests_test_clients_common_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

###############################################################################

EXTRA_DIST += \
	clients/common/tests/wg-test0.conf \
	clients/common/tests/wg-test1.conf \
	clients/common/tests/wg-test2.conf \
	clients/common/tests/wg-test3.conf \
	$(NULL)

###############################################################################

check_programs += clients/common/tests/test-libnm-core-aux

clients_common_tests_test_libnm_core_aux_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(builddir)/shared \
	-I$(srcdir)/shared \
	-I$(builddir)/libnm-core \
	-I$(srcdir)/libnm-core \
	-I$(builddir)/libnm \
	-I$(srcdir)/libnm \
	-DNETWORKMANAGER_COMPILATION_TEST \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

clients_common_tests_test_libnm_core_aux_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

clients_common_tests_test_libnm_core_aux_LDADD = \
	libnm-core/nm-libnm-core-aux/libnm-libnm-core-aux.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	libnm/libnm.la \
	$(GLIB_LIBS) \
	$(NULL)

$(clients_common_tests_test_libnm_core_aux_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(clients_common_tests_test_libnm_core_aux_OBJECTS): $(libnm_lib_h_pub_mkenums)

###############################################################################
# clients/cli
###############################################################################

if BUILD_NMCLI

bin_PROGRAMS += clients/cli/nmcli

clients_cli_nmcli_SOURCES = \
	clients/cli/common.c \
	clients/cli/common.h \
	clients/cli/utils.c \
	clients/cli/utils.h \
	clients/cli/agent.c \
	clients/cli/general.c \
	clients/cli/connections.c \
	clients/cli/connections.h \
	clients/cli/devices.c \
	clients/cli/devices.h \
	clients/cli/settings.c \
	clients/cli/settings.h \
	clients/cli/nmcli.c \
	clients/cli/nmcli.h \
	clients/cli/polkit-agent.c \
	clients/cli/polkit-agent.h \
	$(NULL)

clients_cli_nmcli_CPPFLAGS = \
	-I$(srcdir)/clients/cli \
	$(clients_cppflags) \
	-DG_LOG_DOMAIN=\""nmcli"\" \
	$(NULL)

clients_cli_nmcli_LDADD = \
	clients/common/libnmc.la \
	clients/common/libnmc-base.la \
	libnm-core/nm-libnm-core-aux/libnm-libnm-core-aux.la \
	libnm-core/nm-libnm-core-intern/libnm-libnm-core-intern.la \
	shared/nm-base/libnm-base.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	libnm/nm-libnm-aux/libnm-libnm-aux.la \
	libnm/libnm.la \
	$(GLIB_LIBS) \
	$(READLINE_LIBS)

clients_cli_nmcli_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS)

$(clients_cli_nmcli_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(clients_cli_nmcli_OBJECTS): $(libnm_lib_h_pub_mkenums)

install-data-hook-nmcli:
	$(mkinstalldirs) $(DESTDIR)$(completiondir)
	$(INSTALL_DATA) $(srcdir)/clients/cli/nmcli-completion $(DESTDIR)$(completiondir)/nmcli

install_data_hook += install-data-hook-nmcli

uninstall-hook-nmcli:
	rm -f $(DESTDIR)$(completiondir)/nmcli

uninstall_hook += uninstall-hook-nmcli

endif

###############################################################################

noinst_PROGRAMS += clients/cli/generate-docs-nm-settings-nmcli

clients_cli_generate_docs_nm_settings_nmcli_SOURCES = \
	clients/cli/generate-docs-nm-settings-nmcli.c \
	$(NULL)

clients_cli_generate_docs_nm_settings_nmcli_CPPFLAGS = \
	-I$(srcdir)/clients/common \
	$(clients_cppflags) \
	-DG_LOG_DOMAIN=\""nmcli"\" \
	$(NULL)

clients_cli_generate_docs_nm_settings_nmcli_LDADD = \
	clients/common/libnmc.la \
	clients/common/libnmc-base.la \
	libnm/nm-libnm-aux/libnm-libnm-aux.la \
	libnm-core/nm-libnm-core-aux/libnm-libnm-core-aux.la \
	libnm-core/nm-libnm-core-intern/libnm-libnm-core-intern.la \
	shared/nm-base/libnm-base.la \
	libnm/libnm.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	$(GLIB_LIBS) \
	$(NULL)

clients_cli_generate_docs_nm_settings_nmcli_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

$(clients_cli_generate_docs_nm_settings_nmcli_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(clients_cli_generate_docs_nm_settings_nmcli_OBJECTS): $(libnm_lib_h_pub_mkenums)

###############################################################################

EXTRA_DIST += \
	clients/cli/nmcli-completion \
	clients/cli/meson.build \
	clients/common/settings-docs.xsl \
	clients/common/meson.build \
	clients/common/tests/meson.build

###############################################################################
# clients/tui
###############################################################################

if BUILD_NMTUI

noinst_LIBRARIES += clients/tui/newt/libnmt-newt.a

clients_tui_newt_libnmt_newt_a_SOURCES = \
	clients/tui/newt/nmt-newt.h \
	clients/tui/newt/nmt-newt-types.h \
	clients/tui/newt/nmt-newt-button.c \
	clients/tui/newt/nmt-newt-button.h \
	clients/tui/newt/nmt-newt-button-box.c \
	clients/tui/newt/nmt-newt-button-box.h \
	clients/tui/newt/nmt-newt-checkbox.c \
	clients/tui/newt/nmt-newt-checkbox.h \
	clients/tui/newt/nmt-newt-component.c \
	clients/tui/newt/nmt-newt-component.h \
	clients/tui/newt/nmt-newt-container.c \
	clients/tui/newt/nmt-newt-container.h \
	clients/tui/newt/nmt-newt-entry.c \
	clients/tui/newt/nmt-newt-entry.h \
	clients/tui/newt/nmt-newt-entry-numeric.c \
	clients/tui/newt/nmt-newt-entry-numeric.h \
	clients/tui/newt/nmt-newt-form.c \
	clients/tui/newt/nmt-newt-form.h \
	clients/tui/newt/nmt-newt-grid.c \
	clients/tui/newt/nmt-newt-grid.h \
	clients/tui/newt/nmt-newt-hacks.c \
	clients/tui/newt/nmt-newt-hacks.h \
	clients/tui/newt/nmt-newt-label.c \
	clients/tui/newt/nmt-newt-label.h \
	clients/tui/newt/nmt-newt-listbox.c \
	clients/tui/newt/nmt-newt-listbox.h \
	clients/tui/newt/nmt-newt-popup.c \
	clients/tui/newt/nmt-newt-popup.h \
	clients/tui/newt/nmt-newt-section.c \
	clients/tui/newt/nmt-newt-section.h \
	clients/tui/newt/nmt-newt-separator.c \
	clients/tui/newt/nmt-newt-separator.h \
	clients/tui/newt/nmt-newt-stack.c \
	clients/tui/newt/nmt-newt-stack.h \
	clients/tui/newt/nmt-newt-textbox.c \
	clients/tui/newt/nmt-newt-textbox.h \
	clients/tui/newt/nmt-newt-toggle-button.c \
	clients/tui/newt/nmt-newt-toggle-button.h \
	clients/tui/newt/nmt-newt-utils.c \
	clients/tui/newt/nmt-newt-utils.h \
	clients/tui/newt/nmt-newt-widget.c \
	clients/tui/newt/nmt-newt-widget.h \
	$(NULL)

clients_tui_newt_libnmt_newt_a_CPPFLAGS = \
	$(clients_cppflags) \
	-DG_LOG_DOMAIN=\""nmtui"\" \
	$(NEWT_CFLAGS) \
	$(NULL)

$(clients_tui_newt_libnmt_newt_a_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

bin_PROGRAMS += clients/tui/nmtui

clients_tui_nmtui_SOURCES = \
	clients/tui/nmtui.c \
	clients/tui/nmtui.h \
	clients/tui/nmtui-connect.c \
	clients/tui/nmtui-connect.h \
	clients/tui/nmtui-edit.c \
	clients/tui/nmtui-edit.h \
	clients/tui/nmtui-hostname.c \
	clients/tui/nmtui-hostname.h \
	\
	clients/tui/nm-editor-bindings.c \
	clients/tui/nm-editor-bindings.h \
	clients/tui/nm-editor-utils.c \
	clients/tui/nm-editor-utils.h \
	\
	clients/tui/nmt-address-list.c \
	clients/tui/nmt-address-list.h \
	clients/tui/nmt-connect-connection-list.c \
	clients/tui/nmt-connect-connection-list.h \
	clients/tui/nmt-device-entry.c \
	clients/tui/nmt-device-entry.h \
	clients/tui/nmt-edit-connection-list.c \
	clients/tui/nmt-edit-connection-list.h \
	clients/tui/nmt-editor-grid.c \
	clients/tui/nmt-editor-grid.h \
	clients/tui/nmt-editor-page.c \
	clients/tui/nmt-editor-page.h \
	clients/tui/nmt-editor-page-device.c \
	clients/tui/nmt-editor-page-device.h \
	clients/tui/nmt-editor-section.c \
	clients/tui/nmt-editor-section.h \
	clients/tui/nmt-editor.c \
	clients/tui/nmt-editor.h \
	clients/tui/nmt-ip-entry.c \
	clients/tui/nmt-ip-entry.h \
	clients/tui/nmt-mac-entry.c \
	clients/tui/nmt-mac-entry.h \
	clients/tui/nmt-mtu-entry.c \
	clients/tui/nmt-mtu-entry.h \
	clients/tui/nmt-page-bond.c \
	clients/tui/nmt-page-bond.h \
	clients/tui/nmt-page-bridge.c \
	clients/tui/nmt-page-bridge.h \
	clients/tui/nmt-page-bridge-port.c \
	clients/tui/nmt-page-bridge-port.h \
	clients/tui/nmt-page-dsl.c \
	clients/tui/nmt-page-dsl.h \
	clients/tui/nmt-page-ethernet.c \
	clients/tui/nmt-page-ethernet.h \
	clients/tui/nmt-page-infiniband.c \
	clients/tui/nmt-page-infiniband.h \
	clients/tui/nmt-page-ip-tunnel.c \
	clients/tui/nmt-page-ip-tunnel.h \
	clients/tui/nmt-page-ip4.c \
	clients/tui/nmt-page-ip4.h \
	clients/tui/nmt-page-ip6.c \
	clients/tui/nmt-page-ip6.h \
	clients/tui/nmt-page-ppp.c \
	clients/tui/nmt-page-ppp.h \
	clients/tui/nmt-page-team.c \
	clients/tui/nmt-page-team.h \
	clients/tui/nmt-page-team-port.c \
	clients/tui/nmt-page-team-port.h \
	clients/tui/nmt-page-vlan.c \
	clients/tui/nmt-page-vlan.h \
	clients/tui/nmt-page-wifi.c \
	clients/tui/nmt-page-wifi.h \
	clients/tui/nmt-password-dialog.c \
	clients/tui/nmt-password-dialog.h \
	clients/tui/nmt-password-fields.c \
	clients/tui/nmt-password-fields.h \
	clients/tui/nmt-route-editor.c \
	clients/tui/nmt-route-editor.h \
	clients/tui/nmt-route-entry.c \
	clients/tui/nmt-route-entry.h \
	clients/tui/nmt-route-table.c \
	clients/tui/nmt-route-table.h \
	clients/tui/nmt-slave-list.c \
	clients/tui/nmt-slave-list.h \
	clients/tui/nmt-utils.c \
	clients/tui/nmt-utils.h \
	clients/tui/nmt-widget-list.c \
	clients/tui/nmt-widget-list.h \
	$(NULL)

clients_tui_nmtui_CPPFLAGS = \
	-I$(srcdir)/clients/tui/newt \
	$(clients_cppflags) \
	-DG_LOG_DOMAIN=\""nmtui"\" \
	$(NEWT_CFLAGS) \
	$(NULL)

clients_tui_nmtui_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS)

clients_tui_nmtui_LDADD = \
	clients/tui/newt/libnmt-newt.a \
	clients/common/libnmc.la \
	clients/common/libnmc-base.la \
	libnm/nm-libnm-aux/libnm-libnm-aux.la \
	libnm-core/nm-libnm-core-aux/libnm-libnm-core-aux.la \
	libnm-core/nm-libnm-core-intern/libnm-libnm-core-intern.la \
	shared/nm-base/libnm-base.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	libnm/libnm.la \
	$(GLIB_LIBS) \
	$(NEWT_LIBS) \
	$(NULL)

$(clients_tui_nmtui_OBJECTS): $(libnm_core_lib_h_pub_mkenums)

nmtui_links = nmtui-edit nmtui-connect nmtui-hostname

install-exec-hook-nmtui:
	for link in $(nmtui_links); do \
		$(LN_S) -f nmtui "$(DESTDIR)$(bindir)/$$link"; \
	done

install_exec_hook += install-exec-hook-nmtui

uninstall-hook-nmtui:
	for link in $(nmtui_links); do \
		rm -f "$(DESTDIR)$(bindir)/$$link"; \
	done

uninstall_hook += uninstall-hook-nmtui

endif

EXTRA_DIST += \
	clients/tui/meson.build \
	clients/tui/newt/meson.build

###############################################################################
# clients/nm-cloud-setup
###############################################################################

if BUILD_NM_CLOUD_SETUP

libexec_PROGRAMS += clients/cloud-setup/nm-cloud-setup

clients_cloud_setup_nm_cloud_setup_SOURCES = \
	clients/cloud-setup/main.c \
	clients/cloud-setup/nm-cloud-setup-utils.c \
	clients/cloud-setup/nm-cloud-setup-utils.h \
	clients/cloud-setup/nm-http-client.c \
	clients/cloud-setup/nm-http-client.h \
	clients/cloud-setup/nmcs-provider.c \
	clients/cloud-setup/nmcs-provider.h \
	clients/cloud-setup/nmcs-provider-ec2.c \
	clients/cloud-setup/nmcs-provider-ec2.h \
	clients/cloud-setup/nmcs-provider-gcp.c \
	clients/cloud-setup/nmcs-provider-gcp.h \
	clients/cloud-setup/nmcs-provider-azure.c \
	clients/cloud-setup/nmcs-provider-azure.h \
	$(NULL)

clients_cloud_setup_nm_cloud_setup_CPPFLAGS = \
	$(clients_cppflags) \
	-DG_LOG_DOMAIN=\""nm-cloud-setup"\" \
	$(LIBCURL_CFLAGS) \
	$(NULL)

clients_cloud_setup_nm_cloud_setup_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

clients_cloud_setup_nm_cloud_setup_LDADD = \
	libnm/nm-libnm-aux/libnm-libnm-aux.la \
	libnm-core/nm-libnm-core-aux/libnm-libnm-core-aux.la \
	libnm-core/nm-libnm-core-intern/libnm-libnm-core-intern.la \
	shared/nm-base/libnm-base.la \
	shared/nm-glib-aux/libnm-glib-aux.la \
	shared/nm-std-aux/libnm-std-aux.la \
	shared/libcsiphash.la \
	libnm/libnm.la \
	$(GLIB_LIBS) \
	$(LIBCURL_LIBS) \
	$(NULL)

$(clients_cloud_setup_nm_cloud_setup_OBJECTS): $(libnm_core_lib_h_pub_mkenums)
$(clients_cloud_setup_nm_cloud_setup_OBJECTS): $(libnm_lib_h_pub_mkenums)

if HAVE_SYSTEMD

systemdsystemunit_DATA += \
	clients/cloud-setup/nm-cloud-setup.service \
	clients/cloud-setup/nm-cloud-setup.timer \
	$(NULL)

clients/cloud-setup/nm-cloud-setup.service: $(srcdir)/clients/cloud-setup/nm-cloud-setup.service.in
	$(AM_V_GEN) $(data_edit) $< >$@

install-data-hook-cloud-setup: install-data-hook-dispatcher
	$(INSTALL_SCRIPT) "$(srcdir)/clients/cloud-setup/90-nm-cloud-setup.sh" "$(DESTDIR)$(nmlibdir)/dispatcher.d/no-wait.d/"
	ln -fs no-wait.d/90-nm-cloud-setup.sh "$(DESTDIR)$(nmlibdir)/dispatcher.d/90-nm-cloud-setup.sh"

install_data_hook += install-data-hook-cloud-setup

uninstall-hook-cloud-setup:
	rm -f "$(DESTDIR)$(nmlibdir)/dispatcher.d/no-wait.d/90-nm-cloud-setup.sh"
	rm -f "$(DESTDIR)$(nmlibdir)/dispatcher.d/90-nm-cloud-setup.sh"

uninstall_hook += uninstall-hook-cloud-setup

endif

EXTRA_DIST += \
	clients/cloud-setup/90-nm-cloud-setup.sh \
	clients/cloud-setup/meson.build \
	clients/cloud-setup/nm-cloud-setup.service.in \
	clients/cloud-setup/nm-cloud-setup.timer \
	$(NULL)

CLEANFILES += \
	clients/cloud-setup/nm-cloud-setup.service

endif

###############################################################################
# clients/tests
###############################################################################

check-local-clients-tests-test-client: clients/cli/nmcli clients/tests/test-client.py
	mkdir -p "$(builddir)/clients/tests/"
	"$(builddir)/clients/cli/nmcli" --version
	GI_TYPELIB_PATH="$(abs_builddir)/libnm$${GI_TYPELIB_PATH:+:$$GI_TYPELIB_PATH}" \
	LD_LIBRARY_PATH="$(abs_builddir)/libnm/.libs$${LD_LIBRARY_PATH:+:$$LD_LIBRARY_PATH}" \
	NM_TEST_CLIENT_BUILDDIR="$(abs_builddir)" \
	NM_TEST_CLIENT_NMCLI_PATH=clients/cli/nmcli \
	"$(PYTHON)" \
	$(srcdir)/clients/tests/test-client.py -v &> "$(builddir)/clients/tests/test-client.log" && r=ok; \
	cat "$(builddir)/clients/tests/test-client.log"; \
	test "$$r" = ok

check_local += check-local-clients-tests-test-client

CLEANFILES += clients/tests/test-client.log

EXTRA_DIST += \
	clients/tests/test-client.py \
	clients/tests/test-client.check-on-disk/test_001.expected \
	clients/tests/test-client.check-on-disk/test_002.expected \
	clients/tests/test-client.check-on-disk/test_003.expected \
	clients/tests/test-client.check-on-disk/test_004.expected \
	$(NULL)

check-local-gitlab-ci:
	"$(srcdir)/tools/check-gitlab-ci.sh" "$(srcdir)"

check_local += check-local-gitlab-ci

###############################################################################
# data
###############################################################################

if HAVE_SYSTEMD

systemdsystemunit_DATA += \
	data/NetworkManager.service \
	data/NetworkManager-wait-online.service \
	data/NetworkManager-dispatcher.service \
	$(NULL)

data/NetworkManager.service: $(srcdir)/data/NetworkManager.service.in
	$(AM_V_GEN) $(data_edit) $< >$@

if HAVE_SYSTEMD_200
data/NetworkManager-wait-online.service: $(srcdir)/data/NetworkManager-wait-online.service.in
	$(AM_V_GEN) $(data_edit) $< >$@
else
data/NetworkManager-wait-online.service: $(srcdir)/data/NetworkManager-wait-online-systemd-pre200.service.in
	$(AM_V_GEN) $(data_edit) $< >$@
endif

data/NetworkManager-dispatcher.service: $(srcdir)/data/NetworkManager-dispatcher.service.in
	$(AM_V_GEN) $(data_edit) $< >$@

endif

examples_DATA += data/server.conf

if WITH_UDEV_DIR
udevrulesdir = $(UDEV_DIR)/rules.d
udevrules_DATA = \
	data/84-nm-drivers.rules \
	data/85-nm-unmanaged.rules \
	data/90-nm-thunderbolt.rules
endif

data/server.conf: $(srcdir)/data/server.conf.in
	@$(MKDIR_P) data/
	$(AM_V_GEN) $(data_edit) $< >$@

if WITH_FIREWALLD_ZONE
firewalldzonedir = $(prefix)/lib/firewalld/zones
firewalldzone_DATA = data/nm-shared.xml
endif

EXTRA_DIST += \
	data/84-nm-drivers.rules \
	data/85-nm-unmanaged.rules \
	data/90-nm-thunderbolt.rules \
	data/NetworkManager-dispatcher.service.in \
	data/NetworkManager-wait-online-systemd-pre200.service.in \
	data/NetworkManager-wait-online.service.in \
	data/NetworkManager.service.in \
	data/meson.build \
	data/nm-shared.xml \
	data/server.conf.in \
	$(NULL)

CLEANFILES += \
	data/NetworkManager-dispatcher.service \
	data/NetworkManager-wait-online.service \
	data/NetworkManager.service \
	data/server.conf \
	$(NULL)

###############################################################################
# man
###############################################################################

man/common.ent: man/common.ent.in
	@$(MKDIR_P) man/
	$(AM_V_GEN) $(data_edit) $< >$@

xsltproc_flags = \
	--path man \
	--xinclude \
	--nonet \
	--stringparam man.output.quietly 1 \
	--stringparam funcsynopsis.style ansi \
	--stringparam man.th.extra1.suppress 1 \
	--stringparam man.authors.section.enabled 0 \
	--stringparam man.copyright.section.enabled 0 \
	--stringparam man.th.title.max.length 30

if BUILD_DOCS

man/%.1 man/%.5 man/%.7 man/%.8: man/%.xml man/common.ent
	$(AM_V_GEN) $(XSLTPROC) --output $@ $(xsltproc_flags) http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

endif

man_nm_settings_xml = \
	man/nm-settings-dbus.xml \
	man/nm-settings-ifcfg-rh.xml \
	man/nm-settings-keyfile.xml \
	man/nm-settings-nmcli.xml \
	$(NULL)

if HAVE_INTROSPECTION

man/nm-settings-%.xml: man/nm-settings-%.xsl man/nm-settings-docs-%.xml man/common.ent
	$(AM_V_GEN) $(XSLTPROC) --output $@ $(xsltproc_flags) $< $(word 2,$^)

man/nm-settings-keyfile.xml: man/nm-settings-keyfile.xsl libnm/nm-property-infos-keyfile.xml man/common.ent
	$(AM_V_GEN) $(XSLTPROC) --output $@ $(xsltproc_flags) $< $(word 2,$^)
man/nm-settings-ifcfg-rh.xml: man/nm-settings-ifcfg-rh.xsl libnm/nm-property-infos-ifcfg-rh.xml man/common.ent
	$(AM_V_GEN) $(XSLTPROC) --output $@ $(xsltproc_flags) $< $(word 2,$^)

CLEANFILES += $(man_nm_settings_xml)

endif

man_pages += \
	man/NetworkManager.8 \
	man/NetworkManager.conf.5 \
	man/nm-online.1 \
	man/nm-initrd-generator.8 \
	man/nmcli-examples.7 \
	man/nmcli.1 \
	man/nmtui.1

man_pages_autogen += \
	man/nm-settings-dbus.5 \
	man/nm-settings-keyfile.5 \
	man/nm-settings-nmcli.5 \
	$(NULL)

if CONFIG_PLUGIN_IFCFG_RH
man_pages_autogen += man/nm-settings-ifcfg-rh.5
else
EXTRA_DIST += man/nm-settings-ifcfg-rh.5
dist_dependencies += man/nm-settings-ifcfg-rh.5
endif

if WITH_OPENVSWITCH
man_pages += man/nm-openvswitch.7
else
EXTRA_DIST += man/nm-openvswitch.7
dist_dependencies += man/nm-openvswitch.7
endif

if BUILD_NM_CLOUD_SETUP
man_pages += man/nm-cloud-setup.8
else
EXTRA_DIST += man/nm-cloud-setup.8
dist_dependencies += man/nm-cloud-setup.8
endif

CLEANFILES += \
	man/common.ent

EXTRA_DIST += \
	man/common.ent.in \
	$(man_nm_settings_xml) \
	$(addsuffix .xsl,$(basename $(man_nm_settings_xml))) \
	$(man_pages) \
	$(addsuffix .xml,$(basename $(man_pages))) \
	$(man_pages_autogen) \
	$(NULL)


if HAVE_DOCS

install-data-hook-man:
	for link in $(nmtui_links); do \
		ln -f $(DESTDIR)$(mandir)/man1/nmtui.1 $(DESTDIR)$(mandir)/man1/$$link.1; \
	done; \
	ln -f $(DESTDIR)$(mandir)/man5/NetworkManager.conf.5 $(DESTDIR)$(mandir)/man5/nm-system-settings.conf.5; \
	ln -f $(DESTDIR)$(mandir)/man5/nm-settings-nmcli.5 $(DESTDIR)$(mandir)/man5/nm-settings.5;

install_data_hook += install-data-hook-man

uninstall-hook-man:
	for link in $(nmtui_links); do \
		rm -f $(DESTDIR)$(mandir)/man1/$$link.1; \
	done; \
	rm -f $(DESTDIR)$(mandir)/man5/nm-system-settings.conf.5; \
	rm -f $(DESTDIR)$(mandir)/man5/nm-settings.5;

uninstall_hook += uninstall-hook-man

man_MANS += $(man_pages)
man_MANS += $(man_pages_autogen)

endif

if BUILD_DOCS
CLEANFILES += $(man_pages)
CLEANFILES += $(man_pages_autogen)
endif

dist_dependencies += $(man_pages)
dist_dependencies += $(man_pages_autogen)

EXTRA_DIST += \
	man/meson.build

###############################################################################
# vapi
###############################################################################

if ENABLE_VAPIGEN

VAPIGEN_VAPIS += \
	vapi/libnm.vapi

vapi/libnm.vapi:      $(builddir)/libnm/NM-1.0.gir                   vapi/libnm.deps      vapi/NM-1.0.metadata

vapi_libnm_vapi_METADATADIRS = $(srcdir)/vapi
vapi_libnm_vapi_FILES = $(builddir)/libnm/NM-1.0.gir
vapi_libnm_vapi_DEPS = gio-2.0

vapi_DATA += \
	$(VAPIGEN_VAPIS) \
	$(VAPIGEN_VAPIS:.vapi=.deps)

CLEANFILES += $(VAPIGEN_VAPIS)

endif

EXTRA_DIST += \
	vapi/NM-1.0.metadata \
	vapi/libnm.deps \
	vapi/meson.build

###############################################################################

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)
BUILT_SOURCES += $(gir_DATA)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)
BUILT_SOURCES += $(typelib_DATA)

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA += src/core/org.freedesktop.NetworkManager.conf

###############################################################################

if ENABLE_TESTS
noinst_PROGRAMS += $(check_programs) $(check_programs_norun)
noinst_LTLIBRARIES += $(check_ltlibraries)
else
check_PROGRAMS += $(check_programs) $(check_programs_norun)
check_LTLIBRARIES += $(check_ltlibraries)
endif

plugin_LTLIBRARIES += $(core_plugins)

TESTS += $(check_programs)

EXTRA_DIST += \
	CONTRIBUTING \
	COPYING.LGPL \
	COPYING.GFDL \
	\
	NetworkManager.pc.in \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in \
	linker-script-binary.ver \
	linker-script-devices.ver \
	linker-script-settings.ver \
	src/core/ppp/nm-ppp-plugin.ver \
	Makefile.glib \
	autogen.sh \
	lsan.suppressions \
	valgrind.suppressions \
	meson.build \
	meson_options.txt \
	config.h.meson \
	config-extra.h.meson \
	docs/meson.build \
	\
	po/meson.build \
	\
	shared/nm-default.h \
	shared/nm-gassert-patch.h \
	shared/nm-test-libnm-utils.h \
	shared/nm-test-utils-impl.c \
	shared/nm-utils/nm-compat.c \
	shared/nm-utils/nm-compat.h \
	shared/nm-utils/nm-test-utils.h \
	shared/nm-utils/nm-vpn-editor-plugin-call.h \
	shared/nm-utils/nm-vpn-plugin-macros.h \
	shared/nm-utils/nm-vpn-plugin-utils.c \
	shared/nm-utils/nm-vpn-plugin-utils.h \
	shared/nm-version-macros.h.in \
	shared/meson.build \
	\
	tools/check-config-options.sh \
	tools/check-docs.sh \
	tools/check-exports.sh \
	tools/check-compare-generated.sh \
	tools/check-gitlab-ci.sh \
	tools/create-exports-NetworkManager.sh \
	tools/debug-helper.py \
	tools/meson-post-install.sh \
	tools/run-nm-test.sh \
	tools/test-networkmanager-service.py \
	tools/test-sudo-wrapper.sh \
	tools/enums-to-docbook.pl \
	\
	src/core/settings/plugins/meson.build \
	\
	$(NULL)

CLEANFILES += \
	$(GLIB_GENERATED) \
	$(INTROSPECTION_GIRS) \
	$(typelib_DATA) \
	\
	cscope.in.out \
	cscope.out \
	cscope.po.out \
	\
	$(NULL)

###############################################################################

include Makefile.examples

if WITH_PYTHON_BLACK
check-python-black:
	test "$$NMTST_SKIP_PYTHON_BLACK" == 1 || $(BLACK) --check $(top_srcdir) $(top_srcdir)/examples/python/gi/nm-wg-set
check_local += check-python-black
endif

###############################################################################

check-po-msgfmt:
	@echo "check-po-msgfmt: check $(top_srcdir)/po/*.po files with msgfmt -vc"
	@for f in "$(top_srcdir)/po"/*.po ; do \
		if ! msgfmt -vc "$$f" -o /dev/null &>/dev/null ; then \
			echo "invalid po file: msgfmt -vc $$f -o /dev/null" ; \
			msgfmt -vc "$$f" -o /dev/null ; \
			exit 1 ; \
		fi ; \
	done

check_local += check-po-msgfmt

###############################################################################

check-local: $(check_local)

dist-hook: $(dist_hook)

###############################################################################

install-exec-hook: $(install_exec_hook)

install-data-hook: $(install_data_hook)

uninstall-hook: $(uninstall_hook)

###############################################################################

cscope:
	cscope -b -q -R -sshared -ssrc -slibnm-core -slibnm -sclients;

###############################################################################

check-progs: all $(check_PROGRAMS) $(check_LTLIBRARIES)

###############################################################################

.PRECIOUS: test-suite.log
.DELETE_ON_ERROR:
.PHONY: check-progs cscope dist-configure-check $(check_local) $(dist_hook)
