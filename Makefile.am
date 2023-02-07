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

$(src_libnm_core_public_mkenums_c):                 config-extra.h
$(src_libnm_core_public_mkenums_h):                 config-extra.h
src/core/dhcp/.dirstamp:                            config-extra.h
src/libnm-base/.dirstamp:                           config-extra.h
src/libnm-client-public/.dirstamp:                  config-extra.h
src/libnm-client-public/.dirstamp:                  config-extra.h
src/libnm-core-impl/.dirstamp:                      config-extra.h
src/libnm-core-impl/.dirstamp:                      config-extra.h
src/libnm-crypto/.dirstamp:                         config-extra.h
src/libnm-glib-aux/.dirstamp:                       config-extra.h
src/libnm-glib-aux/tests/.dirstamp:                 config-extra.h
src/libnm-log-core/.dirstamp:                       config-extra.h
src/libnm-log-null/.dirstamp:                       config-extra.h
src/libnm-platform/.dirstamp:                       config-extra.h
src/libnm-platform/tests/.dirstamp:                 config-extra.h
src/libnm-platform/wifi/.dirstamp:                  config-extra.h
src/libnm-platform/wpan/.dirstamp:                  config-extra.h
src/libnm-std-aux/.dirstamp:                        config-extra.h
src/libnm-systemd-shared/.dirstamp:                 config-extra.h
src/libnm-systemd-shared/src/basic/.dirstamp:       config-extra.h
src/libnm-systemd-shared/src/fundamental/.dirstamp: config-extra.h
src/libnm-systemd-shared/src/shared/.dirstamp:      config-extra.h
src/libnm-udev-aux/.dirstamp:                       config-extra.h

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

# Gettext's Makefile has a race with parallel builds during dist.
# Hack around that.
# See also:
#   https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/merge_requests/1094#note_1435313
#   https://lists.gnu.org/archive/html/bug-gettext/2022-06/msg00022.html
#   https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/merge_requests/1405
po/.Makefile.patched:
	sed -i \
	    -e 's#^dist2: \$$(srcdir)/stamp-po \$$(DISTFILES)#dist2: \$$(srcdir)/stamp-po\n\t\$$(MAKE) \$$(DISTFILES)#' \
	    -e 's#^dist2: stamp-po \$$(DISTFILES)#dist2: stamp-po\n\t\$$(MAKE) \$$(DISTFILES)#' \
	    "$(builddir)/po/Makefile" && \
	touch "$(builddir)/po/.Makefile.patched"

DISTCLEANFILES += po/.Makefile.patched

dist: po/.Makefile.patched

dist: $(dist_configure_check) $(dist_dependencies)

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
	-e 's|@NM_CONFIG_DEFAULT_MAIN_DHCP[@]|$(NM_CONFIG_DEFAULT_MAIN_DHCP)|g' \
	-e 's|@NM_CONFIG_DEFAULT_WIFI_BACKEND_TEXT[@]|$(NM_CONFIG_DEFAULT_WIFI_BACKEND_TEXT)|g'

###############################################################################

polkit_policydir = $(datadir)/polkit-1/actions

dist_polkit_policy_in_in_files = \
	data/org.freedesktop.NetworkManager.policy.in.in

dist_polkit_policy_in_files = $(dist_polkit_policy_in_in_files:.policy.in.in=.policy.in)

polkit_policy_DATA = $(dist_polkit_policy_in_files:.policy.in=.policy)

$(polkit_policy_DATA): $(dist_polkit_policy_in_files)
	$(AM_V_GEN)$(MSGFMT) --xml --template $< -d $(top_srcdir)/po -o $@

DISTCLEANFILES += $(polkit_policy_DATA)

###############################################################################

EXTRA_DIST += \
	src/c-stdaux/src/c-stdaux-generic.h \
	src/c-stdaux/src/c-stdaux-gnuc.h \
	src/c-stdaux/src/c-stdaux-unix.h \
	src/c-stdaux/src/c-stdaux.h \
	$(NULL)

###############################################################################

noinst_LTLIBRARIES += src/c-siphash/libc-siphash.la

src_c_siphash_libc_siphash_la_CFLAGS = \
	$(AM_CFLAGS) \
	-std=c11 \
	-I$(srcdir)/src/c-stdaux/src \
	$(NULL)

src_c_siphash_libc_siphash_la_CPPFLAGS = \
	$(CODE_COVERAGE_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

src_c_siphash_libc_siphash_la_LDFLAGS = \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

src_c_siphash_libc_siphash_la_SOURCES = \
	src/c-siphash/src/c-siphash.c \
	src/c-siphash/src/c-siphash.h \
	$(NULL)

###############################################################################

noinst_LTLIBRARIES += src/c-rbtree/libc-rbtree.la

src_c_rbtree_libc_rbtree_la_CFLAGS = \
	$(AM_CFLAGS) \
	-std=c11 \
	-I$(srcdir)/src/c-stdaux/src \
	$(NULL)

src_c_rbtree_libc_rbtree_la_CPPFLAGS = \
	$(CODE_COVERAGE_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

src_c_rbtree_libc_rbtree_la_LDFLAGS = \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

src_c_rbtree_libc_rbtree_la_SOURCES = \
	src/c-rbtree/src/c-rbtree.c \
	src/c-rbtree/src/c-rbtree.h \
	src/c-rbtree/src/c-rbtree-private.h \
	$(NULL)

###############################################################################

noinst_LTLIBRARIES += src/n-acd/libn-acd.la

src_n_acd_libn_acd_la_CFLAGS = \
	$(AM_CFLAGS) \
	-std=c11 \
	-Wno-pointer-arith \
	-Wno-vla \
	$(NULL)

src_n_acd_libn_acd_la_CPPFLAGS = \
	-D_GNU_SOURCE \
	-DSO_ATTACH_BPF=50 \
	$(CODE_COVERAGE_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	-I$(srcdir)/src/c-stdaux/src \
	-I$(srcdir)/src/c-list/src \
	-I$(srcdir)/src/c-siphash/src \
	-I$(srcdir)/src/c-rbtree/src \
	$(NULL)

src_n_acd_libn_acd_la_LDFLAGS = \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

src_n_acd_libn_acd_la_SOURCES = \
	src/n-acd/src/n-acd.c \
	src/n-acd/src/n-acd.h \
	src/n-acd/src/n-acd-private.h \
	src/n-acd/src/n-acd-probe.c \
	src/n-acd/src/util/timer.c \
	src/n-acd/src/util/timer.h \
	$(NULL)

if WITH_EBPF
src_n_acd_libn_acd_la_SOURCES += src/n-acd/src/n-acd-bpf.c
else
src_n_acd_libn_acd_la_SOURCES += src/n-acd/src/n-acd-bpf-fallback.c
endif

###############################################################################

noinst_LTLIBRARIES += src/n-dhcp4/libn-dhcp4.la

src_n_dhcp4_libn_dhcp4_la_CFLAGS = \
	$(AM_CFLAGS) \
	-std=c11 \
	-Wno-error=declaration-after-statement \
	-Wno-pointer-arith \
	$(NULL)

src_n_dhcp4_libn_dhcp4_la_CPPFLAGS = \
	-D_GNU_SOURCE \
	$(CODE_COVERAGE_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	-I$(srcdir)/src/c-stdaux/src \
	-I$(srcdir)/src/c-list/src \
	-I$(srcdir)/src/c-siphash/src \
	$(NULL)

src_n_dhcp4_libn_dhcp4_la_LDFLAGS = \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

src_n_dhcp4_libn_dhcp4_la_SOURCES = \
	src/n-dhcp4/src/n-dhcp4-c-connection.c \
	src/n-dhcp4/src/n-dhcp4-c-lease.c \
	src/n-dhcp4/src/n-dhcp4-c-probe.c \
	src/n-dhcp4/src/n-dhcp4-client.c \
	src/n-dhcp4/src/n-dhcp4-incoming.c \
	src/n-dhcp4/src/n-dhcp4-outgoing.c \
	src/n-dhcp4/src/n-dhcp4-private.h \
	src/n-dhcp4/src/n-dhcp4-socket.c \
	src/n-dhcp4/src/n-dhcp4.h \
	src/n-dhcp4/src/util/packet.c \
	src/n-dhcp4/src/util/packet.h \
	src/n-dhcp4/src/util/socket.c \
	src/n-dhcp4/src/util/socket.h \
	$(NULL)

###############################################################################

noinst_LTLIBRARIES += src/libnm-std-aux/libnm-std-aux.la

src_libnm_std_aux_libnm_std_aux_la_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(CODE_COVERAGE_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

src_libnm_std_aux_libnm_std_aux_la_SOURCES = \
	src/c-list/src/c-list.h \
	src/libnm-std-aux/c-list-util.c \
	src/libnm-std-aux/c-list-util.h \
	src/libnm-std-aux/nm-dbus-compat.h \
	src/libnm-std-aux/nm-default-std.h \
	src/libnm-std-aux/nm-linux-compat.h \
	src/libnm-std-aux/nm-networkmanager-compilation.h \
	src/libnm-std-aux/nm-std-aux.h \
	src/libnm-std-aux/nm-std-utils.c \
	src/libnm-std-aux/nm-std-utils.h \
	src/libnm-std-aux/unaligned.h \
	$(NULL)

src_libnm_std_aux_libnm_std_aux_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

EXTRA_DIST += src/libnm-std-aux/meson.build

###############################################################################

src_libnm_glib_aux_cppflags = \
	$(dflt_cppflags) \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(CODE_COVERAGE_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(NULL)

noinst_LTLIBRARIES += src/libnm-glib-aux/libnm-glib-aux.la

src_libnm_glib_aux_libnm_glib_aux_la_CPPFLAGS = \
	$(src_libnm_glib_aux_cppflags) \
	$(NULL)

src_libnm_glib_aux_libnm_glib_aux_la_SOURCES = \
	src/libnm-glib-aux/nm-c-list.h \
	src/libnm-glib-aux/nm-dbus-aux.c \
	src/libnm-glib-aux/nm-dbus-aux.h \
	src/libnm-glib-aux/nm-dedup-multi.c \
	src/libnm-glib-aux/nm-dedup-multi.h \
	src/libnm-glib-aux/nm-default-glib-i18n-lib.h \
	src/libnm-glib-aux/nm-default-glib-i18n-prog.h \
	src/libnm-glib-aux/nm-default-glib.h \
	src/libnm-glib-aux/nm-enum-utils.c \
	src/libnm-glib-aux/nm-enum-utils.h \
	src/libnm-glib-aux/nm-errno.c \
	src/libnm-glib-aux/nm-errno.h \
	src/libnm-glib-aux/nm-gassert-patch.h \
	src/libnm-glib-aux/nm-glib.h \
	src/libnm-glib-aux/nm-hash-utils.c \
	src/libnm-glib-aux/nm-hash-utils.h \
	src/libnm-glib-aux/nm-inet-utils.c \
	src/libnm-glib-aux/nm-inet-utils.h \
	src/libnm-glib-aux/nm-io-utils.c \
	src/libnm-glib-aux/nm-io-utils.h \
	src/libnm-glib-aux/nm-jansson.h \
	src/libnm-glib-aux/nm-json-aux.c \
	src/libnm-glib-aux/nm-json-aux.h \
	src/libnm-glib-aux/nm-keyfile-aux.c \
	src/libnm-glib-aux/nm-keyfile-aux.h \
	src/libnm-glib-aux/nm-logging-base.c \
	src/libnm-glib-aux/nm-logging-base.h \
	src/libnm-glib-aux/nm-logging-fwd.h \
	src/libnm-glib-aux/nm-logging-syslog.h \
	src/libnm-glib-aux/nm-macros-internal.h \
	src/libnm-glib-aux/nm-obj.h \
	src/libnm-glib-aux/nm-prioq.c \
	src/libnm-glib-aux/nm-prioq.h \
	src/libnm-glib-aux/nm-random-utils.c \
	src/libnm-glib-aux/nm-random-utils.h \
	src/libnm-glib-aux/nm-ref-string.c \
	src/libnm-glib-aux/nm-ref-string.h \
	src/libnm-glib-aux/nm-secret-utils.c \
	src/libnm-glib-aux/nm-secret-utils.h \
	src/libnm-glib-aux/nm-shared-utils.c \
	src/libnm-glib-aux/nm-shared-utils.h \
	src/libnm-glib-aux/nm-str-buf.h \
	src/libnm-glib-aux/nm-test-utils.h \
	src/libnm-glib-aux/nm-time-utils.c \
	src/libnm-glib-aux/nm-time-utils.h \
	src/libnm-glib-aux/nm-uuid.c \
	src/libnm-glib-aux/nm-uuid.h \
	src/libnm-glib-aux/nm-value-type.h \
	$(NULL)

src_libnm_glib_aux_libnm_glib_aux_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

src_libnm_glib_aux_libnm_glib_aux_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

EXTRA_DIST += src/libnm-glib-aux/meson.build

###############################################################################

noinst_LTLIBRARIES += src/libnm-udev-aux/libnm-udev-aux.la

src_libnm_udev_aux_libnm_udev_aux_la_CPPFLAGS = \
	$(src_libnm_glib_aux_cppflags) \
	$(LIBUDEV_CFLAGS) \
	$(NULL)

src_libnm_udev_aux_libnm_udev_aux_la_SOURCES = \
	src/libnm-udev-aux/nm-udev-utils.c \
	src/libnm-udev-aux/nm-udev-utils.h \
	$(NULL)

src_libnm_udev_aux_libnm_udev_aux_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

src_libnm_udev_aux_libnm_udev_aux_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBUDEV_LIBS) \
	$(NULL)

EXTRA_DIST += src/libnm-udev-aux/meson.build

###############################################################################

noinst_LTLIBRARIES += src/libnm-lldp/libnm-lldp.la

src_libnm_lldp_libnm_lldp_la_CFLAGS = \
	$(src_libnm_glib_aux_cppflags) \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(NULL)

src_libnm_lldp_libnm_lldp_la_CPPFLAGS = \
	$(CODE_COVERAGE_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

src_libnm_lldp_libnm_lldp_la_LDFLAGS = \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

src_libnm_lldp_libnm_lldp_la_SOURCES = \
	src/libnm-lldp/nm-lldp-neighbor.c \
	src/libnm-lldp/nm-lldp-neighbor.h \
	src/libnm-lldp/nm-lldp-network.c \
	src/libnm-lldp/nm-lldp-network.h \
	src/libnm-lldp/nm-lldp-rx-internal.h \
	src/libnm-lldp/nm-lldp-rx.c \
	src/libnm-lldp/nm-lldp-rx.h \
	src/libnm-lldp/nm-lldp.h \
	$(NULL)

EXTRA_DIST += src/libnm-lldp/meson.build

###############################################################################

noinst_LTLIBRARIES += src/libnm-base/libnm-base.la

src_libnm_base_libnm_base_la_CPPFLAGS = \
	$(src_libnm_glib_aux_cppflags) \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(NULL)

src_libnm_base_libnm_base_la_SOURCES = \
	src/libnm-base/nm-base.c \
	src/libnm-base/nm-base.h \
	src/libnm-base/nm-config-base.h \
	src/libnm-base/nm-ethtool-base.c \
	src/libnm-base/nm-ethtool-base.h \
	src/libnm-base/nm-ethtool-utils-base.h \
	src/libnm-base/nm-net-aux.c \
	src/libnm-base/nm-net-aux.h \
	src/libnm-base/nm-priv-helper-utils.c \
	src/libnm-base/nm-priv-helper-utils.h \
	$(NULL)

src_libnm_base_libnm_base_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

src_libnm_base_libnm_base_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

EXTRA_DIST += src/libnm-base/meson.build

###############################################################################

noinst_LTLIBRARIES += src/libnm-log-core/libnm-log-core.la

src_libnm_log_core_libnm_log_core_la_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(CODE_COVERAGE_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SYSTEMD_JOURNAL_CFLAGS) \
	$(NULL)

src_libnm_log_core_libnm_log_core_la_SOURCES = \
	src/libnm-log-core/nm-logging.c \
	src/libnm-log-core/nm-logging.h \
	$(NULL)

src_libnm_log_core_libnm_log_core_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

src_libnm_log_core_libnm_log_core_la_LIBADD = \
	$(GLIB_LIBS) \
	$(SYSTEMD_JOURNAL_LIBS) \
	$(NULL)

EXTRA_DIST += src/libnm-log-core/meson.build

noinst_LTLIBRARIES += src/libnm-log-null/libnm-log-null.la

src_libnm_log_null_libnm_log_null_la_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(CODE_COVERAGE_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(NULL)

src_libnm_log_null_libnm_log_null_la_SOURCES = \
	src/libnm-log-null/nm-logging-null.c \
	$(NULL)

src_libnm_log_null_libnm_log_null_la_LIBADD = \
	$(GLIB_LIBS) \
	$(CODE_COVERAGE_LDFLAGS) \
	$(NULL)

EXTRA_DIST += src/libnm-log-null/meson.build

###############################################################################

noinst_LTLIBRARIES += src/libnm-platform/libnm-platform.la

src_libnm_platform_libnm_platform_la_CPPFLAGS = \
	$(src_libnm_glib_aux_cppflags) \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(NULL)

src_libnm_platform_libnm_platform_la_SOURCES = \
	\
	src/linux-headers/ethtool.h \
	src/linux-headers/mptcp.h \
	src/linux-headers/nl80211-vnd-intel.h \
	src/linux-headers/nl802154.h \
	\
	src/nm-compat-headers/linux/if_addr.h \
	\
	src/libnm-platform/nm-linux-platform.c \
	src/libnm-platform/nm-linux-platform.h \
	src/libnm-platform/nm-netlink.c \
	src/libnm-platform/nm-netlink.h \
	src/libnm-platform/nm-platform-private.h \
	src/libnm-platform/nm-platform-utils.c \
	src/libnm-platform/nm-platform-utils.h \
	src/libnm-platform/nm-platform.c \
	src/libnm-platform/nm-platform.h \
	src/libnm-platform/nmp-base.c \
	src/libnm-platform/nmp-base.h \
	src/libnm-platform/nmp-global-tracker.c \
	src/libnm-platform/nmp-global-tracker.h \
	src/libnm-platform/nmp-netns.c \
	src/libnm-platform/nmp-netns.h \
	src/libnm-platform/nmp-object.c \
	src/libnm-platform/nmp-object.h \
	src/libnm-platform/nmp-plobj.c \
	src/libnm-platform/nmp-plobj.h \
	src/libnm-platform/wifi/nm-wifi-utils-nl80211.c \
	src/libnm-platform/wifi/nm-wifi-utils-nl80211.h \
	src/libnm-platform/wifi/nm-wifi-utils-private.h \
	src/libnm-platform/wifi/nm-wifi-utils.c \
	src/libnm-platform/wifi/nm-wifi-utils.h \
	src/libnm-platform/wpan/nm-wpan-utils.c \
	src/libnm-platform/wpan/nm-wpan-utils.h \
	\
	$(NULL)

if WITH_WEXT
src_libnm_platform_libnm_platform_la_SOURCES += \
	src/libnm-platform/wifi/nm-wifi-utils-wext.c \
	src/libnm-platform/wifi/nm-wifi-utils-wext.h \
	$(NULL)
endif

src_libnm_platform_libnm_platform_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

src_libnm_platform_libnm_platform_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

EXTRA_DIST += src/libnm-platform/meson.build

###############################################################################

check_programs += src/libnm-platform/tests/test-nm-platform

src_libnm_platform_tests_test_nm_platform_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(CODE_COVERAGE_CFLAGS) \
	$(SYSTEMD_JOURNAL_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

src_libnm_platform_tests_test_nm_platform_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_libnm_platform_tests_test_nm_platform_LDADD = \
	src/libnm-platform/libnm-platform.la \
	src/libnm-udev-aux/libnm-udev-aux.la \
	src/libnm-base/libnm-base.la \
	src/libnm-log-core/libnm-log-core.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	$(SYSTEMD_JOURNAL_LIBS) \
	$(GLIB_LIBS) \
	$(NULL)

EXTRA_DIST += \
	src/libnm-platform/tests/meson.build \
	$(NULL)

###############################################################################

noinst_LTLIBRARIES += src/libnm-core-aux-intern/libnm-core-aux-intern.la

src_libnm_core_aux_intern_libnm_core_aux_intern_la_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(builddir)/src \
	-I$(srcdir)/src \
	-I$(builddir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-core-public \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

src_libnm_core_aux_intern_libnm_core_aux_intern_la_SOURCES = \
	src/libnm-core-aux-intern/nm-auth-subject.c \
	src/libnm-core-aux-intern/nm-auth-subject.h \
	src/libnm-core-aux-intern/nm-common-macros.h \
	src/libnm-core-aux-intern/nm-libnm-core-utils.c \
	src/libnm-core-aux-intern/nm-libnm-core-utils.h \
	$(NULL)

src_libnm_core_aux_intern_libnm_core_aux_intern_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

src_libnm_core_aux_intern_libnm_core_aux_intern_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

$(src_libnm_core_aux_intern_libnm_core_aux_intern_la_OBJECTS): $(src_libnm_core_public_mkenums_h)

EXTRA_DIST += \
	src/libnm-core-aux-intern/README.md \
	src/libnm-core-aux-intern/meson.build \
	$(NULL)

###############################################################################

noinst_LTLIBRARIES += src/libnm-core-aux-extern/libnm-core-aux-extern.la

src_libnm_core_aux_extern_libnm_core_aux_extern_la_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(builddir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-core-public \
	-I$(srcdir)/src \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

src_libnm_core_aux_extern_libnm_core_aux_extern_la_SOURCES = \
	src/libnm-core-aux-extern/nm-dispatcher-api.h \
	src/libnm-core-aux-extern/nm-libnm-core-aux.c \
	src/libnm-core-aux-extern/nm-libnm-core-aux.h \
	$(NULL)

src_libnm_core_aux_extern_libnm_core_aux_extern_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

src_libnm_core_aux_extern_libnm_core_aux_extern_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

$(src_libnm_core_aux_extern_libnm_core_aux_extern_la_OBJECTS): $(src_libnm_core_public_mkenums_h)

EXTRA_DIST += \
	src/libnm-core-aux-extern/README.md \
	src/libnm-core-aux-extern/meson.build \
	$(NULL)

###############################################################################

noinst_LTLIBRARIES += src/libnm-client-aux-extern/libnm-client-aux-extern.la

src_libnm_client_aux_extern_libnm_client_aux_extern_la_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	-I$(builddir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-client-public \
	-I$(builddir)/src/libnm-client-public \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

src_libnm_client_aux_extern_libnm_client_aux_extern_la_SOURCES = \
	src/libnm-client-aux-extern/nm-libnm-aux.c \
	src/libnm-client-aux-extern/nm-libnm-aux.h \
	$(NULL)

src_libnm_client_aux_extern_libnm_client_aux_extern_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

src_libnm_client_aux_extern_libnm_client_aux_extern_la_LIBADD = \
	$(GLIB_LIBS) \
	src/libnm-client-impl/libnm.la \
	$(NULL)

$(src_libnm_client_aux_extern_libnm_client_aux_extern_la_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_libnm_client_aux_extern_libnm_client_aux_extern_la_OBJECTS): $(src_libnm_client_public_mkenums_h)

EXTRA_DIST += \
	src/libnm-client-aux-extern/README.md \
	src/libnm-client-aux-extern/meson.build \
	src/libnm-client-aux-extern/tests/meson.build \
	$(NULL)

###############################################################################

check_programs += src/libnm-client-aux-extern/tests/test-libnm-client-aux

src_libnm_client_aux_extern_tests_test_libnm_client_aux_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/src/libnm-core-public \
	-I$(builddir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-client-public \
	-I$(builddir)/src/libnm-client-public \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

src_libnm_client_aux_extern_tests_test_libnm_client_aux_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_libnm_client_aux_extern_tests_test_libnm_client_aux_LDADD = \
	src/libnm-core-aux-extern/libnm-core-aux-extern.la \
	src/libnm-core-aux-intern/libnm-core-aux-intern.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	src/libnm-client-impl/libnm.la \
	$(GLIB_LIBS) \
	$(NULL)

$(src_libnm_client_aux_extern_tests_test_libnm_client_aux_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_libnm_client_aux_extern_tests_test_libnm_client_aux_OBJECTS): $(src_libnm_client_public_mkenums_h)

###############################################################################

noinst_LTLIBRARIES += src/libnm-client-test/libnm-client-test.la

src_libnm_client_test_libnm_client_test_la_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	-I$(builddir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-client-public \
	-I$(builddir)/src/libnm-client-public \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

src_libnm_client_test_libnm_client_test_la_SOURCES = \
	src/libnm-client-test/nm-test-libnm-utils.h \
	src/libnm-client-test/nm-test-utils-impl.c \
	$(NULL)

src_libnm_client_test_libnm_client_test_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

src_libnm_client_test_libnm_client_test_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

$(src_libnm_client_test_libnm_client_test_la_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_libnm_client_test_libnm_client_test_la_OBJECTS): $(src_libnm_client_public_mkenums_h)

EXTRA_DIST += \
	src/libnm-client-test/meson.build \
	$(NULL)

###############################################################################

EXTRA_DIST += \
	src/libnm-glib-aux/tests/meson.build \
	$(NULL)

check_programs += src/libnm-glib-aux/tests/test-shared-general

src_libnm_glib_aux_tests_test_shared_general_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

src_libnm_glib_aux_tests_test_shared_general_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_libnm_glib_aux_tests_test_shared_general_LDADD = \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	$(GLIB_LIBS) \
	$(NULL)

###############################################################################

if WITH_JANSSON

check_programs += src/libnm-glib-aux/tests/test-json-aux

src_libnm_glib_aux_tests_test_json_aux_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(JANSSON_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

src_libnm_glib_aux_tests_test_json_aux_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_libnm_glib_aux_tests_test_json_aux_LDADD = \
	$(JANSSON_LIBS) \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
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
	introspection/org.freedesktop.NetworkManager.Device.Loopback.c \
	introspection/org.freedesktop.NetworkManager.Device.Loopback.h \
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
	docs/api/dbus-org.freedesktop.NetworkManager.Device.Loopback.xml \
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
	introspection/org.freedesktop.NetworkManager.Device.Loopback.xml \
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

$(src_libnm_client_impl_libnm_client_impl_la_OBJECTS):               $(introspection_sources)
$(src_libnm_client_impl_libnm_la_OBJECTS):                      $(introspection_sources)

EXTRA_DIST += \
	$(dbusinterfaces_DATA) \
	introspection/meson.build

check-docs:
	$(srcdir)/tools/check-docs.sh "$(srcdir)" "$(builddir)"

check_local += check-docs

###############################################################################

src_libnm_core_impl_lib_h_pub_real = \
	src/libnm-core-public/nm-connection.h \
	src/libnm-core-public/nm-core-types.h \
	src/libnm-core-public/nm-dbus-interface.h \
	src/libnm-core-public/nm-errors.h \
	src/libnm-core-public/nm-keyfile.h \
	src/libnm-core-public/nm-setting-6lowpan.h \
	src/libnm-core-public/nm-setting-8021x.h \
	src/libnm-core-public/nm-setting-adsl.h \
	src/libnm-core-public/nm-setting-bluetooth.h \
	src/libnm-core-public/nm-setting-bond-port.h \
	src/libnm-core-public/nm-setting-bond.h \
	src/libnm-core-public/nm-setting-bridge-port.h \
	src/libnm-core-public/nm-setting-bridge.h \
	src/libnm-core-public/nm-setting-cdma.h \
	src/libnm-core-public/nm-setting-connection.h \
	src/libnm-core-public/nm-setting-dcb.h \
	src/libnm-core-public/nm-setting-dummy.h \
	src/libnm-core-public/nm-setting-ethtool.h \
	src/libnm-core-public/nm-setting-generic.h \
	src/libnm-core-public/nm-setting-gsm.h \
	src/libnm-core-public/nm-setting-hostname.h \
	src/libnm-core-public/nm-setting-infiniband.h \
	src/libnm-core-public/nm-setting-ip-config.h \
	src/libnm-core-public/nm-setting-ip-tunnel.h \
	src/libnm-core-public/nm-setting-ip4-config.h \
	src/libnm-core-public/nm-setting-ip6-config.h \
	src/libnm-core-public/nm-setting-loopback.h \
	src/libnm-core-public/nm-setting-macsec.h \
	src/libnm-core-public/nm-setting-macvlan.h \
	src/libnm-core-public/nm-setting-match.h \
	src/libnm-core-public/nm-setting-olpc-mesh.h \
	src/libnm-core-public/nm-setting-ovs-bridge.h \
	src/libnm-core-public/nm-setting-ovs-dpdk.h \
	src/libnm-core-public/nm-setting-ovs-external-ids.h \
	src/libnm-core-public/nm-setting-ovs-interface.h \
	src/libnm-core-public/nm-setting-ovs-other-config.h \
	src/libnm-core-public/nm-setting-ovs-patch.h \
	src/libnm-core-public/nm-setting-ovs-port.h \
	src/libnm-core-public/nm-setting-ppp.h \
	src/libnm-core-public/nm-setting-pppoe.h \
	src/libnm-core-public/nm-setting-proxy.h \
	src/libnm-core-public/nm-setting-serial.h \
	src/libnm-core-public/nm-setting-sriov.h \
	src/libnm-core-public/nm-setting-tc-config.h \
	src/libnm-core-public/nm-setting-team-port.h \
	src/libnm-core-public/nm-setting-team.h \
	src/libnm-core-public/nm-setting-tun.h \
	src/libnm-core-public/nm-setting-user.h \
	src/libnm-core-public/nm-setting-veth.h \
	src/libnm-core-public/nm-setting-vlan.h \
	src/libnm-core-public/nm-setting-vpn.h \
	src/libnm-core-public/nm-setting-vrf.h \
	src/libnm-core-public/nm-setting-vxlan.h \
	src/libnm-core-public/nm-setting-wifi-p2p.h \
	src/libnm-core-public/nm-setting-wimax.h \
	src/libnm-core-public/nm-setting-wired.h \
	src/libnm-core-public/nm-setting-wireguard.h \
	src/libnm-core-public/nm-setting-wireless-security.h \
	src/libnm-core-public/nm-setting-wireless.h \
	src/libnm-core-public/nm-setting-wpan.h \
	src/libnm-core-public/nm-setting.h \
	src/libnm-core-public/nm-simple-connection.h \
	src/libnm-core-public/nm-utils.h \
	src/libnm-core-public/nm-version-macros.h \
	src/libnm-core-public/nm-version.h \
	src/libnm-core-public/nm-vpn-dbus-interface.h \
	src/libnm-core-public/nm-vpn-editor-plugin.h \
	src/libnm-core-public/nm-vpn-plugin-info.h \
	$(NULL)
src_libnm_core_public_mkenums_h = \
	src/libnm-core-public/nm-core-enum-types.h \
	$(NULL)
src_libnm_core_impl_lib_h_priv = \
	src/libnm-core-impl/nm-connection-private.h \
	src/libnm-core-impl/nm-default-libnm-core.h \
	src/libnm-core-impl/nm-property-compare.h \
	src/libnm-core-impl/nm-setting-private.h \
	src/libnm-core-impl/nm-team-utils.h \
	src/libnm-core-impl/nm-utils-private.h \
	src/libnm-core-intern/nm-core-internal.h \
	src/libnm-core-intern/nm-keyfile-internal.h \
	src/libnm-core-intern/nm-keyfile-utils.h \
	src/libnm-core-intern/nm-meta-setting-base-impl.h \
	src/libnm-core-intern/nm-meta-setting-base.h \
	$(NULL)
src_libnm_core_impl_lib_c_settings_real = \
	src/libnm-core-impl/nm-setting-6lowpan.c \
	src/libnm-core-impl/nm-setting-8021x.c \
	src/libnm-core-impl/nm-setting-adsl.c \
	src/libnm-core-impl/nm-setting-bluetooth.c \
	src/libnm-core-impl/nm-setting-bond-port.c \
	src/libnm-core-impl/nm-setting-bond.c \
	src/libnm-core-impl/nm-setting-bridge-port.c \
	src/libnm-core-impl/nm-setting-bridge.c \
	src/libnm-core-impl/nm-setting-cdma.c \
	src/libnm-core-impl/nm-setting-connection.c \
	src/libnm-core-impl/nm-setting-dcb.c \
	src/libnm-core-impl/nm-setting-dummy.c \
	src/libnm-core-impl/nm-setting-ethtool.c \
	src/libnm-core-impl/nm-setting-generic.c \
	src/libnm-core-impl/nm-setting-gsm.c \
	src/libnm-core-impl/nm-setting-hostname.c \
	src/libnm-core-impl/nm-setting-infiniband.c \
	src/libnm-core-impl/nm-setting-ip-config.c \
	src/libnm-core-impl/nm-setting-ip-tunnel.c \
	src/libnm-core-impl/nm-setting-ip4-config.c \
	src/libnm-core-impl/nm-setting-ip6-config.c \
	src/libnm-core-impl/nm-setting-loopback.c \
	src/libnm-core-impl/nm-setting-macsec.c \
	src/libnm-core-impl/nm-setting-macvlan.c \
	src/libnm-core-impl/nm-setting-match.c \
	src/libnm-core-impl/nm-setting-olpc-mesh.c \
	src/libnm-core-impl/nm-setting-ovs-bridge.c \
	src/libnm-core-impl/nm-setting-ovs-dpdk.c \
	src/libnm-core-impl/nm-setting-ovs-external-ids.c \
	src/libnm-core-impl/nm-setting-ovs-interface.c \
	src/libnm-core-impl/nm-setting-ovs-other-config.c \
	src/libnm-core-impl/nm-setting-ovs-patch.c \
	src/libnm-core-impl/nm-setting-ovs-port.c \
	src/libnm-core-impl/nm-setting-ppp.c \
	src/libnm-core-impl/nm-setting-pppoe.c \
	src/libnm-core-impl/nm-setting-proxy.c \
	src/libnm-core-impl/nm-setting-serial.c \
	src/libnm-core-impl/nm-setting-sriov.c \
	src/libnm-core-impl/nm-setting-tc-config.c \
	src/libnm-core-impl/nm-setting-team-port.c \
	src/libnm-core-impl/nm-setting-team.c \
	src/libnm-core-impl/nm-setting-tun.c \
	src/libnm-core-impl/nm-setting-user.c \
	src/libnm-core-impl/nm-setting-veth.c \
	src/libnm-core-impl/nm-setting-vlan.c \
	src/libnm-core-impl/nm-setting-vpn.c \
	src/libnm-core-impl/nm-setting-vrf.c \
	src/libnm-core-impl/nm-setting-vxlan.c \
	src/libnm-core-impl/nm-setting-wifi-p2p.c \
	src/libnm-core-impl/nm-setting-wimax.c \
	src/libnm-core-impl/nm-setting-wired.c \
	src/libnm-core-impl/nm-setting-wireguard.c \
	src/libnm-core-impl/nm-setting-wireless-security.c \
	src/libnm-core-impl/nm-setting-wireless.c \
	src/libnm-core-impl/nm-setting-wpan.c \
	$(NULL)
src_libnm_core_impl_lib_c_real = \
	$(src_libnm_core_impl_lib_c_settings_real) \
	src/libnm-core-impl/nm-connection.c \
	src/libnm-core-impl/nm-errors.c \
	src/libnm-core-impl/nm-keyfile-utils.c \
	src/libnm-core-impl/nm-keyfile.c \
	src/libnm-core-impl/nm-meta-setting-base-impl.c \
	src/libnm-core-impl/nm-property-compare.c \
	src/libnm-core-impl/nm-setting.c \
	src/libnm-core-impl/nm-simple-connection.c \
	src/libnm-core-impl/nm-team-utils.c \
	src/libnm-core-impl/nm-utils.c \
	src/libnm-core-impl/nm-vpn-editor-plugin.c \
	src/libnm-core-impl/nm-vpn-plugin-info.c \
	$(NULL)

src_libnm_core_public_mkenums_c = \
	src/libnm-core-public/nm-core-enum-types.c \
	$(NULL)

libnminclude_HEADERS += \
	$(src_libnm_core_impl_lib_h_pub_real)

nodist_libnminclude_HEADERS += \
	$(src_libnm_core_public_mkenums_h)

EXTRA_DIST += \
	src/libnm-core-impl/README.md \
	src/libnm-core-impl/meson.build \
	src/libnm-core-intern/README.md \
	src/libnm-core-intern/meson.build \
	src/libnm-core-public/README.md \
	src/libnm-core-public/meson.build \
	$(NULL)

###############################################################################

dflt_cppflags_libnm_core = \
	$(dflt_cppflags) \
	-I$(builddir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-core-public \
	-I$(srcdir)/src \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(LIBUDEV_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

noinst_LTLIBRARIES += src/libnm-core-impl/libnm-core-impl.la

src/libnm-client-public/nm-enum-types.h.stamp:           src/libnm-client-public/.dirstamp
src/libnm-client-public/nm-enum-types.c.stamp:           src/libnm-client-public/.dirstamp

GLIB_GENERATED += \
	$(src_libnm_core_public_mkenums_h) \
	$(src_libnm_core_public_mkenums_c) \
	$(NULL)
nm_core_enum_types_sources = $(src_libnm_core_impl_lib_h_pub_real)

nm_core_enum_types_MKENUMS_C_FLAGS = --fhead '\#undef G_LOG_DOMAIN\n\#include "src/libnm-core-impl/nm-default-libnm-core.h"\n'

src/libnm-core-public/nm-core-enum-types.h.stamp:                           src/libnm-core-public/.dirstamp
src/libnm-core-public/nm-core-enum-types.c.stamp:                           src/libnm-core-public/.dirstamp

$(src_nm_dispatcher_libnm_dispatcher_core_la_OBJECTS):                      $(src_libnm_core_public_mkenums_h)
$(src_nm_dispatcher_nm_dispatcher_OBJECTS):                                 $(src_libnm_core_public_mkenums_h)
$(src_libnm_core_impl_libnm_core_impl_la_OBJECTS):                          $(src_libnm_core_public_mkenums_h)
$(src_libnm_client_impl_libnm_la_OBJECTS):                                  $(src_libnm_core_public_mkenums_h)
$(src_contrib_tests_libnm_vpn_plugin_utils_test_la_OBJECTS):                $(src_libnm_core_public_mkenums_h)
$(src_core_NetworkManager_OBJECTS):                                         $(src_libnm_core_public_mkenums_h)
$(src_core_devices_adsl_libnm_device_plugin_adsl_la_OBJECTS):               $(src_libnm_core_public_mkenums_h)
$(src_core_devices_bluetooth_libnm_device_plugin_bluetooth_la_OBJECTS):     $(src_libnm_core_public_mkenums_h)
$(src_core_devices_team_libnm_device_plugin_team_la_OBJECTS):               $(src_libnm_core_public_mkenums_h)
$(src_core_devices_wifi_libnm_device_plugin_wifi_la_OBJECTS):               $(src_libnm_core_public_mkenums_h)
$(src_core_devices_wwan_libnm_device_plugin_wwan_la_OBJECTS):               $(src_libnm_core_public_mkenums_h)
$(src_core_devices_ovs_libnm_device_plugin_ovs_la_OBJECTS):                 $(src_libnm_core_public_mkenums_h)

src_libnm_core_impl_libnm_core_impl_la_CPPFLAGS = \
	$(dflt_cppflags_libnm_core) \
	-I$(srcdir)/src/libnm-core-intern/ \
	$(NULL)

src_libnm_core_impl_libnm_core_impl_la_SOURCES = \
	$(src_libnm_core_impl_lib_h_pub_real) \
	$(src_libnm_core_impl_lib_h_priv) \
	$(src_libnm_core_impl_lib_c_real)

nodist_src_libnm_core_impl_libnm_core_impl_la_SOURCES = \
	$(src_libnm_core_public_mkenums_h) \
	$(src_libnm_core_public_mkenums_c) \
	$(NULL)

src_libnm_core_impl_libnm_core_impl_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

src_libnm_core_impl_libnm_core_impl_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

EXTRA_DIST += \
	src/libnm-core-impl/meson.build \
	$(NULL)

src/libnm-core-public/nm-vpn-dbus-types.xml: src/libnm-core-public/nm-vpn-dbus-interface.h tools/enums-to-docbook.pl
	@$(MKDIR_P) src/libnm-core-public/
	$(AM_V_GEN) @PERL@ $(srcdir)/tools/enums-to-docbook.pl 'nm-vpn-dbus-types' 'VPN Plugin D-Bus API Types' $< >$@

src/libnm-core-public/nm-dbus-types.xml: src/libnm-core-public/nm-dbus-interface.h tools/enums-to-docbook.pl
	@$(MKDIR_P) src/libnm-core-public/
	$(AM_V_GEN) @PERL@ $(srcdir)/tools/enums-to-docbook.pl 'nm-dbus-types' 'NetworkManager D-Bus API Types' $< >$@

BUILT_SOURCES += \
	src/libnm-core-public/nm-vpn-dbus-types.xml \
	src/libnm-core-public/nm-dbus-types.xml

dist_dependencies += \
	src/libnm-core-public/nm-vpn-dbus-types.xml \
	src/libnm-core-public/nm-dbus-types.xml

###############################################################################

noinst_LTLIBRARIES += src/libnm-crypto/libnm-crypto.la

src_libnm_crypto_libnm_crypto_la_SOURCES = \
	src/libnm-crypto/nm-crypto-impl.h \
	src/libnm-crypto/nm-crypto.c \
	src/libnm-crypto/nm-crypto.h \
	$(NULL)

src_libnm_crypto_libnm_crypto_la_CPPFLAGS = \
	$(dflt_cppflags_libnm_core) \
	$(NULL)

src_libnm_crypto_libnm_crypto_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

src_libnm_crypto_libnm_crypto_la_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	$(NULL)

if HAVE_CRYPTO_GNUTLS
if WITH_GNUTLS
libnm_crypto_lib = src/libnm-crypto/libnm-crypto-gnutls.la
else
check_ltlibraries += src/libnm-crypto/libnm-crypto-gnutls.la
endif

src_libnm_crypto_libnm_crypto_gnutls_la_SOURCES = src/libnm-crypto/nm-crypto-gnutls.c
src_libnm_crypto_libnm_crypto_gnutls_la_CPPFLAGS = \
	$(src_libnm_core_impl_libnm_core_impl_la_CPPFLAGS) \
	$(GNUTLS_CFLAGS)
src_libnm_crypto_libnm_crypto_gnutls_la_LDFLAGS = \
	$(src_libnm_core_impl_libnm_core_impl_la_LDFLAGS)
src_libnm_crypto_libnm_crypto_gnutls_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GNUTLS_LIBS)
endif

if HAVE_CRYPTO_NSS
if WITH_NSS
libnm_crypto_lib = src/libnm-crypto/libnm-crypto-nss.la
else
check_ltlibraries += src/libnm-crypto/libnm-crypto-nss.la
endif

src_libnm_crypto_libnm_crypto_nss_la_SOURCES = src/libnm-crypto/nm-crypto-nss.c
src_libnm_crypto_libnm_crypto_nss_la_CPPFLAGS = \
	$(src_libnm_core_impl_libnm_core_impl_la_CPPFLAGS) \
	$(NSS_CFLAGS)
src_libnm_crypto_libnm_crypto_nss_la_LDFLAGS = \
	$(src_libnm_core_impl_libnm_core_impl_la_LDFLAGS)
src_libnm_crypto_libnm_crypto_nss_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NSS_LIBS)
endif

if !WITH_GNUTLS
if !WITH_NSS
libnm_crypto_lib = src/libnm-crypto/libnm-crypto-null.la
else
check_ltlibraries += src/libnm-crypto/libnm-crypto-null.la
endif
else
check_ltlibraries += src/libnm-crypto/libnm-crypto-null.la
endif

src_libnm_crypto_libnm_crypto_null_la_SOURCES = src/libnm-crypto/nm-crypto-null.c
src_libnm_crypto_libnm_crypto_null_la_CPPFLAGS = \
	$(src_libnm_core_impl_libnm_core_impl_la_CPPFLAGS) \
	$(NULL)
src_libnm_crypto_libnm_crypto_null_la_LDFLAGS = \
	$(src_libnm_core_impl_libnm_core_impl_la_LDFLAGS) \
	$(NULL)
src_libnm_crypto_libnm_crypto_null_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

noinst_LTLIBRARIES += $(libnm_crypto_lib)

EXTRA_DIST += \
	src/libnm-crypto/README.md \
	src/libnm-crypto/meson.build \
	src/libnm-crypto/nm-crypto-gnutls.c \
	src/libnm-crypto/nm-crypto-nss.c \
	$(NULL)

###############################################################################

check_programs += \
	src/libnm-core-impl/tests/test-compare \
	src/libnm-core-impl/tests/test-crypto \
	src/libnm-core-impl/tests/test-general \
	src/libnm-core-impl/tests/test-keyfile \
	src/libnm-core-impl/tests/test-secrets \
	src/libnm-core-impl/tests/test-setting \
	src/libnm-core-impl/tests/test-settings-defaults

GLIB_GENERATED += \
	src/libnm-core-impl/tests/nm-core-tests-enum-types.h \
	src/libnm-core-impl/tests/nm-core-tests-enum-types.c
nm_core_tests_enum_types_sources = src/libnm-core-impl/tests/test-general-enums.h
nm_core_tests_enum_types_MKENUMS_C_FLAGS = --fhead '\#undef G_LOG_DOMAIN\n\#include "src/libnm-core-impl/nm-default-libnm-core.h"\n'

src/libnm-core-impl/tests/nm-core-tests-enum-types.h.stamp: src/libnm-core-impl/tests/.dirstamp
src/libnm-core-impl/tests/nm-core-tests-enum-types.c.stamp: src/libnm-core-impl/tests/.dirstamp

$(src_libnm_core_impl_tests_test_general_OBJECTS): src/libnm-core-impl/tests/nm-core-tests-enum-types.h

src_libnm_core_impl_tests_cppflags = \
	-I$(builddir)/src/libnm-core-impl/tests \
	-I$(srcdir)/src/libnm-core-impl/tests \
	-I$(srcdir)/src/libnm-core-impl \
	-I$(srcdir)/src/ \
	-I$(builddir)/src/ \
	$(dflt_cppflags_libnm_core) \
	$(SANITIZER_EXEC_CFLAGS) \
	$(NULL)

src_libnm_core_impl_tests_test_compare_CPPFLAGS = $(src_libnm_core_impl_tests_cppflags)
src_libnm_core_impl_tests_test_crypto_CPPFLAGS = $(src_libnm_core_impl_tests_cppflags)
src_libnm_core_impl_tests_test_general_CPPFLAGS = $(src_libnm_core_impl_tests_cppflags)
src_libnm_core_impl_tests_test_keyfile_CPPFLAGS = $(src_libnm_core_impl_tests_cppflags)
src_libnm_core_impl_tests_test_secrets_CPPFLAGS = $(src_libnm_core_impl_tests_cppflags)
src_libnm_core_impl_tests_test_setting_CPPFLAGS = $(src_libnm_core_impl_tests_cppflags)
src_libnm_core_impl_tests_test_settings_defaults_CPPFLAGS = $(src_libnm_core_impl_tests_cppflags)

src_libnm_core_impl_tests_test_general_SOURCES = \
	src/libnm-core-impl/tests/test-general-enums.h \
	src/libnm-core-impl/tests/test-general.c \
	$(NULL)

nodist_src_libnm_core_impl_tests_test_general_SOURCES = \
	src/libnm-core-impl/tests/nm-core-tests-enum-types.c \
	src/libnm-core-impl/tests/nm-core-tests-enum-types.h \
	$(NULL)

src_libnm_core_impl_tests_ldadd = \
	src/libnm-core-aux-extern/libnm-core-aux-extern.la \
	src/libnm-core-impl/libnm-core-impl.la \
	src/libnm-crypto/libnm-crypto.la \
	$(libnm_crypto_lib) \
	src/libnm-core-aux-intern/libnm-core-aux-intern.la \
	src/libnm-base/libnm-base.la \
	src/libnm-systemd-shared/libnm-systemd-shared.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	$(GLIB_LIBS) \
	$(NULL)

src_libnm_core_impl_tests_ldflags = \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_libnm_core_impl_tests_test_compare_LDADD = $(src_libnm_core_impl_tests_ldadd)
src_libnm_core_impl_tests_test_crypto_LDADD = $(src_libnm_core_impl_tests_ldadd)
src_libnm_core_impl_tests_test_general_LDADD = $(src_libnm_core_impl_tests_ldadd)
src_libnm_core_impl_tests_test_keyfile_LDADD = $(src_libnm_core_impl_tests_ldadd)
src_libnm_core_impl_tests_test_secrets_LDADD = $(src_libnm_core_impl_tests_ldadd)
src_libnm_core_impl_tests_test_setting_LDADD = $(src_libnm_core_impl_tests_ldadd)
src_libnm_core_impl_tests_test_settings_defaults_LDADD = $(src_libnm_core_impl_tests_ldadd)

src_libnm_core_impl_tests_test_compare_LDFLAGS = $(src_libnm_core_impl_tests_ldflags)
src_libnm_core_impl_tests_test_crypto_LDFLAGS = $(src_libnm_core_impl_tests_ldflags)
src_libnm_core_impl_tests_test_general_LDFLAGS = $(src_libnm_core_impl_tests_ldflags)
src_libnm_core_impl_tests_test_keyfile_LDFLAGS = $(src_libnm_core_impl_tests_ldflags)
src_libnm_core_impl_tests_test_secrets_LDFLAGS = $(src_libnm_core_impl_tests_ldflags)
src_libnm_core_impl_tests_test_setting_LDFLAGS = $(src_libnm_core_impl_tests_ldflags)
src_libnm_core_impl_tests_test_settings_defaults_LDFLAGS = $(src_libnm_core_impl_tests_ldflags)

$(src_libnm_core_impl_tests_test_compare_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_libnm_core_impl_tests_test_crypto_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_libnm_core_impl_tests_test_general_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_libnm_core_impl_tests_test_keyfile_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_libnm_core_impl_tests_test_secrets_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_libnm_core_impl_tests_test_setting_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_libnm_core_impl_tests_test_settings_defaults_OBJECTS): $(src_libnm_core_public_mkenums_h)

# test-cert.p12 created with:
#
# openssl pkcs12 -export \
#    -in test_key_and_cert.pem \
#    -inkey test_key_and_cert.pem \
#    -certfile test_ca_cert.pem \
#    -name "test-pkcs12" \
#    -out test-cert.p12

EXTRA_DIST += \
	src/libnm-core-impl/tests/certs/ca-no-ending-newline.pem \
	src/libnm-core-impl/tests/certs/pkcs8-decrypted.der \
	src/libnm-core-impl/tests/certs/pkcs8-enc-key.pem \
	src/libnm-core-impl/tests/certs/pkcs8-noenc-key.pem \
	src/libnm-core-impl/tests/certs/test2_ca_cert.pem \
	src/libnm-core-impl/tests/certs/test2-cert.p12 \
	src/libnm-core-impl/tests/certs/test2_key_and_cert.pem \
	src/libnm-core-impl/tests/certs/test-aes-128-key.pem \
	src/libnm-core-impl/tests/certs/test-aes-256-key.pem \
	src/libnm-core-impl/tests/certs/test-aes-128-ec-key.pem \
	src/libnm-core-impl/tests/certs/test-aes-256-ec-key.pem \
	src/libnm-core-impl/tests/certs/test_ca_cert.der \
	src/libnm-core-impl/tests/certs/test_ca_cert.pem \
	src/libnm-core-impl/tests/certs/test-ca-cert.pem \
	src/libnm-core-impl/tests/certs/test-cert.p12 \
	src/libnm-core-impl/tests/certs/test_key_and_cert.pem \
	src/libnm-core-impl/tests/certs/test-key-and-cert.pem \
	src/libnm-core-impl/tests/certs/test-key-only-decrypted.der \
	src/libnm-core-impl/tests/certs/test-key-only-decrypted.pem \
	src/libnm-core-impl/tests/certs/test-ec-key-only-decrypted.der \
	src/libnm-core-impl/tests/certs/test-ec-key-only-decrypted.pem \
	src/libnm-core-impl/tests/certs/test-key-only.pem \
	src/libnm-core-impl/tests/certs/test-tpm2wrapped-key.pem \
	src/libnm-core-impl/tests/nm-core-tests-enum-types.c.template \
	src/libnm-core-impl/tests/nm-core-tests-enum-types.h.template \
	src/libnm-core-impl/tests/meson.build

###############################################################################

libnm_lib_h_pub_real = \
	src/libnm-client-public/NetworkManager.h \
	src/libnm-client-public/nm-access-point.h \
	src/libnm-client-public/nm-active-connection.h \
	src/libnm-client-public/nm-autoptr.h \
	src/libnm-client-public/nm-checkpoint.h \
	src/libnm-client-public/nm-client.h \
	src/libnm-client-public/nm-conn-utils.h \
	src/libnm-client-public/nm-device-6lowpan.h \
	src/libnm-client-public/nm-device-adsl.h \
	src/libnm-client-public/nm-device-bond.h \
	src/libnm-client-public/nm-device-bridge.h \
	src/libnm-client-public/nm-device-bt.h \
	src/libnm-client-public/nm-device-dummy.h \
	src/libnm-client-public/nm-device-ethernet.h \
	src/libnm-client-public/nm-device-generic.h \
	src/libnm-client-public/nm-device-infiniband.h \
	src/libnm-client-public/nm-device-ip-tunnel.h \
	src/libnm-client-public/nm-device-loopback.h \
	src/libnm-client-public/nm-device-macsec.h \
	src/libnm-client-public/nm-device-macvlan.h \
	src/libnm-client-public/nm-device-modem.h \
	src/libnm-client-public/nm-device-olpc-mesh.h \
	src/libnm-client-public/nm-device-ovs-bridge.h \
	src/libnm-client-public/nm-device-ovs-interface.h \
	src/libnm-client-public/nm-device-ovs-port.h \
	src/libnm-client-public/nm-device-ppp.h \
	src/libnm-client-public/nm-device-team.h \
	src/libnm-client-public/nm-device-tun.h \
	src/libnm-client-public/nm-device-veth.h \
	src/libnm-client-public/nm-device-vlan.h \
	src/libnm-client-public/nm-device-vrf.h \
	src/libnm-client-public/nm-device-vxlan.h \
	src/libnm-client-public/nm-device-wifi-p2p.h \
	src/libnm-client-public/nm-device-wifi.h \
	src/libnm-client-public/nm-device-wimax.h \
	src/libnm-client-public/nm-device-wireguard.h \
	src/libnm-client-public/nm-device-wpan.h \
	src/libnm-client-public/nm-device.h \
	src/libnm-client-public/nm-dhcp-config.h \
	src/libnm-client-public/nm-ethtool-utils.h \
	src/libnm-client-public/nm-ip-config.h \
	src/libnm-client-public/nm-object.h \
	src/libnm-client-public/nm-remote-connection.h \
	src/libnm-client-public/nm-secret-agent-old.h \
	src/libnm-client-public/nm-vpn-connection.h \
	src/libnm-client-public/nm-vpn-editor.h \
	src/libnm-client-public/nm-vpn-plugin-old.h \
	src/libnm-client-public/nm-vpn-service-plugin.h \
	src/libnm-client-public/nm-wifi-p2p-peer.h \
	src/libnm-client-public/nm-wimax-nsp.h \
	$(NULL)
src_libnm_client_public_mkenums_h = \
	src/libnm-client-public/nm-enum-types.h \
	$(NULL)
libnm_lib_h_priv = \
	src/libnm-client-impl/nm-dbus-helpers.h \
	src/libnm-client-aux-extern/nm-default-client.h \
	src/libnm-client-impl/nm-default-libnm.h \
	src/libnm-client-impl/nm-device-private.h \
	src/libnm-client-impl/nm-dhcp4-config.h \
	src/libnm-client-impl/nm-dhcp6-config.h \
	src/libnm-client-impl/nm-dns-manager.h \
	src/libnm-client-impl/nm-ip4-config.h \
	src/libnm-client-impl/nm-ip6-config.h \
	src/libnm-client-impl/nm-libnm-utils.h \
	src/libnm-client-impl/nm-object-private.h \
	src/libnm-client-impl/nm-remote-connection-private.h \
	$(NULL)
libnm_lib_c_real = \
	src/libnm-client-impl/nm-client.c \
	src/libnm-client-impl/nm-object.c \
	src/libnm-client-impl/nm-device.c \
	src/libnm-client-impl/nm-active-connection.c \
	\
	src/libnm-client-impl/nm-access-point.c \
	src/libnm-client-impl/nm-checkpoint.c \
	src/libnm-client-impl/nm-conn-utils.c \
	src/libnm-client-impl/nm-dbus-helpers.c \
	src/libnm-client-impl/nm-device-6lowpan.c \
	src/libnm-client-impl/nm-device-adsl.c \
	src/libnm-client-impl/nm-device-bond.c \
	src/libnm-client-impl/nm-device-bridge.c \
	src/libnm-client-impl/nm-device-bt.c \
	src/libnm-client-impl/nm-device-dummy.c \
	src/libnm-client-impl/nm-device-ethernet.c \
	src/libnm-client-impl/nm-device-generic.c \
	src/libnm-client-impl/nm-device-infiniband.c \
	src/libnm-client-impl/nm-device-ip-tunnel.c \
	src/libnm-client-impl/nm-device-loopback.c \
	src/libnm-client-impl/nm-device-macsec.c \
	src/libnm-client-impl/nm-device-macvlan.c \
	src/libnm-client-impl/nm-device-modem.c \
	src/libnm-client-impl/nm-device-olpc-mesh.c \
	src/libnm-client-impl/nm-device-ovs-bridge.c \
	src/libnm-client-impl/nm-device-ovs-interface.c \
	src/libnm-client-impl/nm-device-ovs-port.c \
	src/libnm-client-impl/nm-device-ppp.c \
	src/libnm-client-impl/nm-device-team.c \
	src/libnm-client-impl/nm-device-tun.c \
	src/libnm-client-impl/nm-device-veth.c \
	src/libnm-client-impl/nm-device-vlan.c \
	src/libnm-client-impl/nm-device-vrf.c \
	src/libnm-client-impl/nm-device-vxlan.c \
	src/libnm-client-impl/nm-device-wifi-p2p.c \
	src/libnm-client-impl/nm-device-wifi.c \
	src/libnm-client-impl/nm-device-wimax.c \
	src/libnm-client-impl/nm-device-wireguard.c \
	src/libnm-client-impl/nm-device-wpan.c \
	src/libnm-client-impl/nm-dhcp-config.c \
	src/libnm-client-impl/nm-dhcp4-config.c \
	src/libnm-client-impl/nm-dhcp6-config.c \
	src/libnm-client-impl/nm-dns-manager.c \
	src/libnm-client-impl/nm-ip-config.c \
	src/libnm-client-impl/nm-ip4-config.c \
	src/libnm-client-impl/nm-ip6-config.c \
	src/libnm-client-impl/nm-libnm-utils.c \
	src/libnm-client-impl/nm-remote-connection.c \
	src/libnm-client-impl/nm-secret-agent-old.c \
	src/libnm-client-impl/nm-vpn-connection.c \
	src/libnm-client-impl/nm-vpn-editor.c \
	src/libnm-client-impl/nm-vpn-plugin-old.c \
	src/libnm-client-impl/nm-vpn-service-plugin.c \
	src/libnm-client-impl/nm-wifi-p2p-peer.c \
	src/libnm-client-impl/nm-wimax-nsp.c \
	$(NULL)
src_libnm_client_public_mkenums_c = \
	src/libnm-client-public/nm-enum-types.c \
	$(NULL)

libnminclude_HEADERS += \
	$(libnm_lib_h_pub_real)

nodist_libnminclude_HEADERS += \
	$(src_libnm_client_public_mkenums_h)

EXTRA_DIST += src/libnm-client-public/meson.build

###############################################################################

noinst_PROGRAMS += src/libnm-core-impl/gen-metadata-nm-settings-libnm-core

src_libnm_core_impl_gen_metadata_nm_settings_libnm_core_SOURCES = \
	src/libnm-core-impl/gen-metadata-nm-settings-libnm-core.c \
	$(NULL)

src_libnm_core_impl_gen_metadata_nm_settings_libnm_core_CPPFLAGS = \
	$(clients_cppflags) \
	$(NULL)

src_libnm_core_impl_gen_metadata_nm_settings_libnm_core_LDADD = \
	src/libnm-core-impl/libnm-core-impl.la \
	src/libnm-crypto/libnm-crypto.la \
	$(libnm_crypto_lib) \
	src/libnm-core-aux-intern/libnm-core-aux-intern.la \
	src/libnm-base/libnm-base.la \
	src/libnm-systemd-shared/libnm-systemd-shared.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	$(GLIB_LIBS) \
	$(NULL)

src_libnm_core_impl_gen_metadata_nm_settings_libnm_core_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

$(src_libnm_core_impl_gen_metadata_nm_settings_libnm_core_OBJECTS): $(src_libnm_core_public_mkenums_h)

###############################################################################

noinst_LTLIBRARIES += src/libnm-client-impl/libnm-client-impl.la

src_libnm_client_impl_libnm_client_impl_la_CPPFLAGS = \
	-I$(builddir)/src/libnm-client-public \
	-I$(srcdir)/src/libnm-client-public \
	-I$(srcdir)/src \
	$(dflt_cppflags_libnm_core) \
	$(INTROSPECTION_CFLAGS) \
	$(NULL)

src_libnm_client_impl_libnm_client_impl_la_SOURCES = \
	$(libnm_lib_c_real) \
	$(NULL)

nodist_src_libnm_client_impl_libnm_client_impl_la_SOURCES = \
	$(src_libnm_client_public_mkenums_h) \
	$(src_libnm_client_public_mkenums_c) \
	$(NULL)

src_libnm_client_impl_libnm_client_impl_la_LIBADD = \
	src/libnm-core-aux-extern/libnm-core-aux-extern.la \
	src/libnm-core-impl/libnm-core-impl.la \
	src/libnm-crypto/libnm-crypto.la \
	$(libnm_crypto_lib) \
	src/libnm-core-aux-intern/libnm-core-aux-intern.la \
	src/libnm-base/libnm-base.la \
	introspection/libnmdbus.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-systemd-shared/libnm-systemd-shared.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-udev-aux/libnm-udev-aux.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	$(GLIB_LIBS) \
	$(DL_LIBS) \
	$(LIBUDEV_LIBS) \
	$(NULL)

$(src_libnm_client_impl_libnm_client_impl_la_OBJECTS) : $(src_libnm_client_public_mkenums_h)
$(src_libnm_client_impl_libnm_client_impl_la_OBJECTS) : $(src_libnm_core_public_mkenums_h)

###############################################################################

lib_LTLIBRARIES += src/libnm-client-impl/libnm.la

GLIB_GENERATED += \
	$(src_libnm_client_public_mkenums_h) \
	$(src_libnm_client_public_mkenums_c)
nm_enum_types_sources = \
	$(src_libnm_client_public_mkenums_h) \
	$(libnm_lib_h_pub_real)
nm_enum_types_MKENUMS_H_FLAGS = --fhead '\#include "nm-core-enum-types.h"\n'
nm_enum_types_MKENUMS_C_FLAGS = --fhead '\#undef G_LOG_DOMAIN\n\#include "libnm-client-impl/nm-default-libnm.h"\n'

$(src_nm_dispatcher_nm_dispatcher_OBJECTS):                             $(src_libnm_client_public_mkenums_h)
$(src_nm_dispatcher_libnm_dispatcher_core_la_OBJECTS):                  $(src_libnm_client_public_mkenums_h)
$(src_libnm_client_impl_libnm_la_OBJECTS):                              $(src_libnm_client_public_mkenums_h)
$(src_contrib_tests_libnm_vpn_plugin_utils_test_la_OBJECTS):            $(src_libnm_client_public_mkenums_h)

src_libnm_client_impl_libnm_la_CPPFLAGS = \
	-I$(builddir)/src/libnm-client-public \
	-I$(srcdir)/src/libnm-client-public \
	-I$(srcdir)/src \
	$(dflt_cppflags_libnm_core) \
	$(LIBUDEV_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

src_libnm_client_impl_libnm_la_SOURCES = \
	$(libnm_lib_h_pub_real) \
	$(libnm_lib_h_priv) \
	$(NULL)

EXTRA_src_libnm_client_impl_libnm_la_DEPENDENCIES = \
	src/libnm-client-impl/libnm.ver

src_libnm_client_impl_libnm_la_LIBADD = \
	src/libnm-client-impl/libnm-client-impl.la \
	$(NULL)

src_libnm_client_impl_libnm_la_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/src/libnm-client-impl/libnm.ver" \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_LIB_LDFLAGS) \
	-version-info "1:0:1"

check-local-exports-libnm: src/libnm-client-impl/libnm.la
	$(srcdir)/tools/check-exports.sh "$(builddir)/src/libnm-client-impl/.libs/libnm.so" "$(srcdir)/src/libnm-client-impl/libnm.ver"

check_local += check-local-exports-libnm

pkgconfig_DATA += src/libnm-client-impl/libnm.pc

DISTCLEANFILES += \
	src/libnm-client-impl/libnm.pc

EXTRA_DIST += \
	src/libnm-client-public/nm-enum-types.c.template \
	src/libnm-client-public/nm-enum-types.h.template \
	\
	src/libnm-client-impl/libnm.pc.in \
	src/libnm-client-impl/libnm.ver

###############################################################################

src/libnm-client-impl/NM-1.0.gir: src/libnm-client-impl/libnm.la
src_libnm_client_impl_NM_1_0_gir_INCLUDES = Gio-2.0
src_libnm_client_impl_NM_1_0_gir_PACKAGES = gio-2.0
src_libnm_client_impl_NM_1_0_gir_EXPORT_PACKAGES = libnm
src_libnm_client_impl_NM_1_0_gir_CFLAGS = \
	$(filter-out -DGLIB_VERSION_%, $(src_libnm_client_impl_libnm_la_CPPFLAGS)) \
	-DNETWORKMANAGER_COMPILATION \
	$(NULL)
src_libnm_client_impl_NM_1_0_gir_LIBS = src/libnm-client-impl/libnm.la
src_libnm_client_impl_NM_1_0_gir_FILES = \
	$(src_libnm_core_public_mkenums_h) \
	$(src_libnm_core_impl_lib_h_pub_real) \
	$(src_libnm_core_public_mkenums_c) \
	$(src_libnm_core_impl_lib_c_real) \
	$(src_libnm_client_public_mkenums_h) \
	$(libnm_lib_h_pub_real) \
	$(src_libnm_client_public_mkenums_c) \
	$(libnm_lib_c_real)
src_libnm_client_impl_NM_1_0_gir_SCANNERFLAGS = --warn-all --identifier-prefix=NM --symbol-prefix=nm

src/libnm-client-impl/libnm.typelib: src/libnm-client-impl/libnm.gir
	$(INTROSPECTION_COMPILER) --includedir=$(srcdir)/src/libnm-core-public --includedir=$(builddir)/src/libnm-core-public --includedir=$(srcdir)/libnm-client-public --includedir=$(builddir)/libnm-client-public $< -o $@


libnm_noinst_data = \
	src/libnm-core-impl/gen-metadata-nm-settings-libnm-core.xml \
	src/nmcli/gen-metadata-nm-settings-nmcli.xml \
	man/nm-settings-docs-dbus.xml \
	man/nm-settings-docs-nmcli.xml \
	src/libnm-client-impl/nm-property-infos-dbus.xml \
	src/libnm-client-impl/nm-property-infos-ifcfg-rh.xml \
	src/libnm-client-impl/nm-property-infos-keyfile.xml \
	src/libnm-client-impl/nm-property-infos-nmcli.xml \
	src/libnm-client-impl/nm-settings-docs-gir.xml \
	src/libnmc-setting/settings-docs-input.xml \
	$(NULL)

if HAVE_INTROSPECTION
INTROSPECTION_GIRS += src/libnm-client-impl/NM-1.0.gir
noinst_DATA += $(libnm_noinst_data)
DISTCLEANFILES += $(libnm_noinst_data)

EXTRA_DIST += \
	src/nmcli/gen-metadata-nm-settings-nmcli.xml.in \
	src/libnm-core-impl/gen-metadata-nm-settings-libnm-core.xml.in

src_libnm_client_impl_NM_1_0_typelib = src/libnm-client-impl/NM-1.0.typelib
else
src_libnm_client_impl_NM_1_0_typelib =
endif

###############################################################################

if BUILD_DOCS
src/nmcli/gen-metadata-nm-settings-nmcli.xml: src/nmcli/gen-metadata-nm-settings-nmcli
	$(AM_V_GEN) src/nmcli/gen-metadata-nm-settings-nmcli > "$@"
check-local-gen-metadata-nm-settings-nmcli: src/nmcli/gen-metadata-nm-settings-nmcli.xml
	$(srcdir)/tools/check-compare-generated.sh "$(srcdir)/src/nmcli/gen-metadata-nm-settings-nmcli.xml.in" "$(builddir)/src/nmcli/gen-metadata-nm-settings-nmcli.xml"
check_local += check-local-gen-metadata-nm-settings-nmcli
DISTCLEANFILES += src/nmcli/gen-metadata-nm-settings-nmcli.xml

src/libnm-core-impl/gen-metadata-nm-settings-libnm-core.xml: src/libnm-core-impl/gen-metadata-nm-settings-libnm-core
	$(AM_V_GEN) src/libnm-core-impl/gen-metadata-nm-settings-libnm-core > "$@"
check-local-gen-metadata-nm-settings-libnm-core: src/libnm-core-impl/gen-metadata-nm-settings-libnm-core.xml
	$(srcdir)/tools/check-compare-generated.sh "$(srcdir)/src/libnm-core-impl/gen-metadata-nm-settings-libnm-core.xml.in" "$(builddir)/src/libnm-core-impl/gen-metadata-nm-settings-libnm-core.xml"
check_local += check-local-gen-metadata-nm-settings-libnm-core
DISTCLEANFILES += src/libnm-core-impl/gen-metadata-nm-settings-libnm-core.xml
else
src/nmcli/gen-metadata-nm-settings-nmcli.xml: src/nmcli/gen-metadata-nm-settings-nmcli.xml.in
	$(AM_V_GEN) cp $^ $@
check-local-gen-metadata-nm-settings-nmcli:

src/libnm-core-impl/gen-metadata-nm-settings-libnm-core.xml: src/libnm-core-impl/gen-metadata-nm-settings-libnm-core.xml.in
	$(AM_V_GEN) cp $^ $@
check-local-gen-metadata-nm-settings-libnm-core:
endif

libnm_docs_sources = $(src_libnm_core_impl_lib_c_settings_real)

src/libnm-client-impl/nm-property-infos-%.xml: tools/generate-docs-nm-property-infos.py src/libnm-core-impl/libnm-core-impl.la $(libnm_docs_sources)
	$(AM_V_GEN) \
		"$(PYTHON)" \
		$(srcdir)/tools/generate-docs-nm-property-infos.py \
		$(patsubst nm-property-infos-%.xml,%,$(notdir $@)) \
		$@ \
		$(wordlist 3,1000,$^)

src/libnm-client-impl/nm-settings-docs-gir.xml: tools/generate-docs-nm-settings-docs-gir.py src/libnm-client-impl/NM-1.0.gir src/libnm-client-impl/NM-1.0.typelib src/libnm-client-impl/libnm.la $(libnm_docs_sources)
	$(AM_V_GEN) \
	export GI_TYPELIB_PATH=$(abs_builddir)/src/libnm-client-impl$${GI_TYPELIB_PATH:+:$$GI_TYPELIB_PATH}; \
	export LD_LIBRARY_PATH=$(abs_builddir)/src/libnm-client-impl/.libs$${LD_LIBRARY_PATH:+:$$LD_LIBRARY_PATH}; \
	$(call set_sanitizer_env,$(abs_builddir)/src/libnm-client-impl/.libs/libnm.so); \
	"$(PYTHON)" \
	$(srcdir)/tools/generate-docs-nm-settings-docs-gir.py \
		--gir $(builddir)/src/libnm-client-impl/NM-1.0.gir \
		--output $@

man/nm-settings-docs-nmcli.xml: src/nmcli/gen-metadata-nm-settings-nmcli.xml src/libnm-client-impl/nm-property-infos-nmcli.xml src/libnm-client-impl/nm-settings-docs-gir.xml tools/generate-docs-nm-settings-docs-merge.py man/common.ent
	$(AM_V_GEN) "$(PYTHON)" $(srcdir)/tools/generate-docs-nm-settings-docs-merge.py --only-from-first $@ $(wordlist 1,3,$^)

src/libnmc-setting/settings-docs-input.xml: src/libnm-client-impl/nm-property-infos-nmcli.xml src/libnm-client-impl/nm-settings-docs-gir.xml tools/generate-docs-nm-settings-docs-merge.py
	$(AM_V_GEN) "$(PYTHON)" $(srcdir)/tools/generate-docs-nm-settings-docs-merge.py $@ $(wordlist 1,2,$^)

man/nm-settings-docs-%.xml: src/libnm-client-impl/nm-property-infos-%.xml src/libnm-client-impl/nm-settings-docs-gir.xml tools/generate-docs-nm-settings-docs-merge.py man/common.ent
	$(AM_V_GEN) "$(PYTHON)" $(srcdir)/tools/generate-docs-nm-settings-docs-merge.py $@ $(wordlist 1,2,$^)


EXTRA_DIST += \
	tools/generate-docs-nm-property-infos.py \
	tools/generate-docs-nm-settings-docs-merge.py \
	tools/generate-docs-nm-settings-docs-gir.py \
	src/libnm-client-impl/meson.build \
	$(NULL)

###############################################################################

check_programs += src/libnm-client-impl/tests/test-libnm

src_libnm_client_impl_tests_programs_req_introspection = \
	src/libnm-client-impl/tests/test-nm-client \
	src/libnm-client-impl/tests/test-remote-settings-client \
	src/libnm-client-impl/tests/test-secret-agent

check-local-libnm-gir: $(builddir)/src/libnm-client-impl/NM-1.0.gir
check-local-libnm-gir: $(srcdir)/src/libnm-client-impl/libnm.ver
check-local-libnm-gir:
	"$(PYTHON)" $(srcdir)/src/libnm-client-impl/tests/test-gir.py \
		--gir $(builddir)/src/libnm-client-impl/NM-1.0.gir \
		--ver $(srcdir)/src/libnm-client-impl/libnm.ver

if HAVE_INTROSPECTION
check_programs += $(src_libnm_client_impl_tests_programs_req_introspection)
check_local += check-local-libnm-gir
else
check_programs_norun += $(src_libnm_client_impl_tests_programs_req_introspection)
endif

src_libnm_client_impl_tests_cppflags = \
	-I$(srcdir)/src/libnm-client-public \
	-I$(builddir)/src/libnm-client-public \
	$(dflt_cppflags_libnm_core) \
	$(SANITIZER_EXEC_CFLAGS) \
	$(NULL)

src_libnm_client_impl_tests_ldadd = \
	src/libnm-client-test/libnm-client-test.la \
	src/libnm-client-impl/libnm-client-impl.la \
	$(GLIB_LIBS) \
	$(NULL)

src_libnm_client_impl_tests_ldflags = \
	$(SANITIZER_EXEC_LDFLAGS)

src_libnm_client_impl_tests_test_libnm_CPPFLAGS = $(src_libnm_client_impl_tests_cppflags)
src_libnm_client_impl_tests_test_nm_client_CPPFLAGS = $(src_libnm_client_impl_tests_cppflags)
src_libnm_client_impl_tests_test_remote_settings_client_CPPFLAGS = $(src_libnm_client_impl_tests_cppflags)
src_libnm_client_impl_tests_test_secret_agent_CPPFLAGS = $(src_libnm_client_impl_tests_cppflags)

src_libnm_client_impl_tests_test_libnm_SOURCES = \
	src/contrib/nm-compat.c \
	src/contrib/nm-compat.h \
	src/libnm-client-impl/tests/test-libnm.c \
	$(NULL)

src_libnm_client_impl_tests_test_libnm_LDADD = $(src_libnm_client_impl_tests_ldadd)
src_libnm_client_impl_tests_test_nm_client_LDADD = $(src_libnm_client_impl_tests_ldadd)
src_libnm_client_impl_tests_test_remote_settings_client_LDADD = $(src_libnm_client_impl_tests_ldadd)
src_libnm_client_impl_tests_test_secret_agent_LDADD = $(src_libnm_client_impl_tests_ldadd)

src_libnm_client_impl_tests_test_libnm_LDFLAGS = $(src_libnm_client_impl_tests_ldflags)
src_libnm_client_impl_tests_test_nm_client_LDFLAGS = $(src_libnm_client_impl_tests_ldflags)
src_libnm_client_impl_tests_test_remote_settings_client_LDFLAGS = $(src_libnm_client_impl_tests_ldflags)
src_libnm_client_impl_tests_test_secret_agent_LDFLAGS = $(src_libnm_client_impl_tests_ldflags)

$(src_libnm_client_impl_tests_test_libnm_OBJECTS):                  $(src_libnm_core_public_mkenums_h) $(src_libnm_client_public_mkenums_h)
$(src_libnm_client_impl_tests_test_nm_client_OBJECTS):              $(src_libnm_core_public_mkenums_h) $(src_libnm_client_public_mkenums_h)
$(src_libnm_client_impl_tests_test_remote_settings_client_OBJECTS): $(src_libnm_core_public_mkenums_h) $(src_libnm_client_public_mkenums_h)
$(src_libnm_client_impl_tests_test_secret_agent_OBJECTS):           $(src_libnm_core_public_mkenums_h) $(src_libnm_client_public_mkenums_h)

# tools/test-networkmanager-service.py uses libnm's typelib. Ensure it
# is built first.
$(src_libnm_client_impl_tests_test_nm_client_OBJECTS):              $(src_libnm_client_impl_NM_1_0_typelib)
$(src_libnm_client_impl_tests_test_remote_settings_client_OBJECTS): $(src_libnm_client_impl_NM_1_0_typelib)
$(src_libnm_client_impl_tests_test_secret_agent_OBJECTS):           $(src_libnm_client_impl_NM_1_0_typelib)

EXTRA_DIST += \
	src/libnm-client-impl/tests/meson.build \
	src/libnm-client-impl/tests/test-gir.py

###############################################################################

# just test, that we can build "nm-vpn-plugin-utils.c"

check_ltlibraries += src/contrib/tests/libnm-vpn-plugin-utils-test.la

src_contrib_tests_libnm_vpn_plugin_utils_test_la_SOURCES = \
	src/contrib/nm-vpn-plugin-utils.c \
	src/contrib/nm-vpn-plugin-utils.h \
	$(NULL)

src_contrib_tests_libnm_vpn_plugin_utils_test_la_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	-I$(builddir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-client-public \
	-I$(builddir)/src/libnm-client-public \
	$(GLIB_CFLAGS) \
	$(SANITIZER_EXEC_CFLAGS) \
	$(NULL)

src_contrib_tests_libnm_vpn_plugin_utils_test_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NULL)

EXTRA_DIST += \
	src/contrib/meson.build \
	src/contrib/tests/meson.build \
	$(NULL)

###############################################################################
# src/core/
###############################################################################

src_core_cppflags_base = \
	-I$(srcdir)/src/core \
	$(dflt_cppflags_libnm_core) \
	$(SANITIZER_EXEC_CFLAGS) \
	$(NULL)

src_core_cppflags_base_test = \
	$(src_core_cppflags_base) \
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
	$(NULL)

if REQUIRE_ROOT_TESTS
src_core_cppflags_test += -DREQUIRE_ROOT_TESTS=1
endif

src_core_ldflags = $(CODE_COVERAGE_LDFLAGS)

sbin_PROGRAMS += \
	src/core/NetworkManager

noinst_LTLIBRARIES += \
	src/core/libNetworkManagerBase.la \
	src/core/libNetworkManager.la \
	src/libnm-systemd-core/libnm-systemd-core.la \
	$(NULL)

check-config-options:
	$(srcdir)/tools/check-config-options.sh "$(srcdir)"

check_local += check-config-options

###############################################################################

libsystemd_cppflags = \
	$(dflt_cppflags) \
	-I$(srcdir)/src/ \
	-I$(builddir)/src/ \
	-I$(srcdir)/src/libnm-systemd-shared/ \
	-I$(srcdir)/src/libnm-systemd-shared/sd-adapt-shared \
	-I$(srcdir)/src/libnm-systemd-shared/src/basic \
	-I$(srcdir)/src/libnm-systemd-shared/src/fundamental \
	-I$(srcdir)/src/libnm-systemd-shared/src/shared \
	$(LIBSYSTEMD_NM_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	$(NULL)

noinst_LTLIBRARIES += src/libnm-systemd-shared/libnm-systemd-shared.la

src_libnm_systemd_shared_libnm_systemd_shared_la_CPPFLAGS = \
	$(libsystemd_cppflags) \
	$(NULL)

src_libnm_systemd_shared_libnm_systemd_shared_la_SOURCES = \
	src/libnm-systemd-shared/nm-default-systemd-shared.h \
	src/libnm-systemd-shared/nm-sd-utils-shared.c \
	src/libnm-systemd-shared/nm-sd-utils-shared.h \
	src/libnm-systemd-shared/sd-adapt-shared/architecture.h \
	src/libnm-systemd-shared/sd-adapt-shared/arphrd-list.h \
	src/libnm-systemd-shared/sd-adapt-shared/blockdev-util.h \
	src/libnm-systemd-shared/sd-adapt-shared/build.h \
	src/libnm-systemd-shared/sd-adapt-shared/chase-symlinks.h \
	src/libnm-systemd-shared/sd-adapt-shared/copy.h \
	src/libnm-systemd-shared/sd-adapt-shared/def.h \
	src/libnm-systemd-shared/sd-adapt-shared/dhcp-server-internal.h \
	src/libnm-systemd-shared/sd-adapt-shared/dirent-util.h \
	src/libnm-systemd-shared/sd-adapt-shared/errno-list.h \
	src/libnm-systemd-shared/sd-adapt-shared/filesystems.h \
	src/libnm-systemd-shared/sd-adapt-shared/glob-util.h \
	src/libnm-systemd-shared/sd-adapt-shared/gunicode.h \
	src/libnm-systemd-shared/sd-adapt-shared/hmac.h \
	src/libnm-systemd-shared/sd-adapt-shared/idn-util.h \
	src/libnm-systemd-shared/sd-adapt-shared/ioprio.h \
	src/libnm-systemd-shared/sd-adapt-shared/memfd-util.h \
	src/libnm-systemd-shared/sd-adapt-shared/missing_fs.h \
	src/libnm-systemd-shared/sd-adapt-shared/missing_ioprio.h \
	src/libnm-systemd-shared/sd-adapt-shared/missing_keyctl.h \
	src/libnm-systemd-shared/sd-adapt-shared/missing_magic.h \
	src/libnm-systemd-shared/sd-adapt-shared/missing_network.h \
	src/libnm-systemd-shared/sd-adapt-shared/missing_sched.h \
	src/libnm-systemd-shared/sd-adapt-shared/missing_syscall_def.h \
	src/libnm-systemd-shared/sd-adapt-shared/missing_timerfd.h \
	src/libnm-systemd-shared/sd-adapt-shared/mkdir.h \
	src/libnm-systemd-shared/sd-adapt-shared/namespace-util.h \
	src/libnm-systemd-shared/sd-adapt-shared/netif-util.h \
	src/libnm-systemd-shared/sd-adapt-shared/nm-sd-adapt-shared.h \
	src/libnm-systemd-shared/sd-adapt-shared/nulstr-util.h \
	src/libnm-systemd-shared/sd-adapt-shared/os-util.h \
	src/libnm-systemd-shared/sd-adapt-shared/raw-clone.h \
	src/libnm-systemd-shared/sd-adapt-shared/rlimit-util.h \
	src/libnm-systemd-shared/sd-adapt-shared/sync-util.h \
	src/libnm-systemd-shared/sd-adapt-shared/sysctl-util.h \
	src/libnm-systemd-shared/sd-adapt-shared/terminal-util.h \
	src/libnm-systemd-shared/sd-adapt-shared/unaligned.h \
	src/libnm-systemd-shared/sd-adapt-shared/virt.h \
	src/libnm-systemd-shared/src/basic/alloc-util.c \
	src/libnm-systemd-shared/src/basic/alloc-util.h \
	src/libnm-systemd-shared/src/basic/async.h \
	src/libnm-systemd-shared/src/basic/cgroup-util.h \
	src/libnm-systemd-shared/src/basic/dns-def.h \
	src/libnm-systemd-shared/src/basic/env-file.c \
	src/libnm-systemd-shared/src/basic/env-file.h \
	src/libnm-systemd-shared/src/basic/env-util.c \
	src/libnm-systemd-shared/src/basic/env-util.h \
	src/libnm-systemd-shared/src/basic/errno-util.h \
	src/libnm-systemd-shared/src/basic/escape.c \
	src/libnm-systemd-shared/src/basic/escape.h \
	src/libnm-systemd-shared/src/basic/ether-addr-util.c \
	src/libnm-systemd-shared/src/basic/ether-addr-util.h \
	src/libnm-systemd-shared/src/basic/extract-word.c \
	src/libnm-systemd-shared/src/basic/extract-word.h \
	src/libnm-systemd-shared/src/basic/fd-util.c \
	src/libnm-systemd-shared/src/basic/fd-util.h \
	src/libnm-systemd-shared/src/basic/fileio.c \
	src/libnm-systemd-shared/src/basic/fileio.h \
	src/libnm-systemd-shared/src/basic/format-util.c \
	src/libnm-systemd-shared/src/basic/format-util.h \
	src/libnm-systemd-shared/src/basic/fs-util.c \
	src/libnm-systemd-shared/src/basic/fs-util.h \
	src/libnm-systemd-shared/src/basic/glyph-util.c \
	src/libnm-systemd-shared/src/basic/glyph-util.h \
	src/libnm-systemd-shared/src/basic/hash-funcs.c \
	src/libnm-systemd-shared/src/basic/hash-funcs.h \
	src/libnm-systemd-shared/src/basic/hashmap.c \
	src/libnm-systemd-shared/src/basic/hashmap.h \
	src/libnm-systemd-shared/src/basic/hexdecoct.c \
	src/libnm-systemd-shared/src/basic/hexdecoct.h \
	src/libnm-systemd-shared/src/basic/hostname-util.c \
	src/libnm-systemd-shared/src/basic/hostname-util.h \
	src/libnm-systemd-shared/src/basic/in-addr-util.c \
	src/libnm-systemd-shared/src/basic/in-addr-util.h \
	src/libnm-systemd-shared/src/basic/inotify-util.c \
	src/libnm-systemd-shared/src/basic/inotify-util.h \
	src/libnm-systemd-shared/src/basic/io-util.c \
	src/libnm-systemd-shared/src/basic/io-util.h \
	src/libnm-systemd-shared/src/basic/list.h \
	src/libnm-systemd-shared/src/basic/locale-util.c \
	src/libnm-systemd-shared/src/basic/locale-util.h \
	src/libnm-systemd-shared/src/basic/log.h \
	src/libnm-systemd-shared/src/basic/macro.h \
	src/libnm-systemd-shared/src/basic/memory-util.c \
	src/libnm-systemd-shared/src/basic/memory-util.h \
	src/libnm-systemd-shared/src/basic/mempool.c \
	src/libnm-systemd-shared/src/basic/mempool.h \
	src/libnm-systemd-shared/src/basic/missing_fcntl.h \
	src/libnm-systemd-shared/src/basic/missing_random.h \
	src/libnm-systemd-shared/src/basic/missing_socket.h \
	src/libnm-systemd-shared/src/basic/missing_stat.h \
	src/libnm-systemd-shared/src/basic/missing_syscall.h \
	src/libnm-systemd-shared/src/basic/missing_type.h \
	src/libnm-systemd-shared/src/basic/ordered-set.c \
	src/libnm-systemd-shared/src/basic/ordered-set.h \
	src/libnm-systemd-shared/src/basic/parse-util.c \
	src/libnm-systemd-shared/src/basic/parse-util.h \
	src/libnm-systemd-shared/src/basic/path-util.c \
	src/libnm-systemd-shared/src/basic/path-util.h \
	src/libnm-systemd-shared/src/basic/prioq.c \
	src/libnm-systemd-shared/src/basic/prioq.h \
	src/libnm-systemd-shared/src/basic/process-util.c \
	src/libnm-systemd-shared/src/basic/process-util.h \
	src/libnm-systemd-shared/src/basic/random-util.c \
	src/libnm-systemd-shared/src/basic/random-util.h \
	src/libnm-systemd-shared/src/basic/ratelimit.c \
	src/libnm-systemd-shared/src/basic/ratelimit.h \
	src/libnm-systemd-shared/src/basic/set.h \
	src/libnm-systemd-shared/src/basic/signal-util.c \
	src/libnm-systemd-shared/src/basic/signal-util.h \
	src/libnm-systemd-shared/src/basic/siphash24.h \
	src/libnm-systemd-shared/src/basic/socket-util.c \
	src/libnm-systemd-shared/src/basic/socket-util.h \
	src/libnm-systemd-shared/src/basic/sort-util.h \
	src/libnm-systemd-shared/src/basic/sparse-endian.h \
	src/libnm-systemd-shared/src/basic/stat-util.c \
	src/libnm-systemd-shared/src/basic/stat-util.h \
	src/libnm-systemd-shared/src/basic/stdio-util.h \
	src/libnm-systemd-shared/src/basic/string-table.c \
	src/libnm-systemd-shared/src/basic/string-table.h \
	src/libnm-systemd-shared/src/basic/string-util.c \
	src/libnm-systemd-shared/src/basic/string-util.h \
	src/libnm-systemd-shared/src/basic/strv.c \
	src/libnm-systemd-shared/src/basic/strv.h \
	src/libnm-systemd-shared/src/basic/strxcpyx.c \
	src/libnm-systemd-shared/src/basic/strxcpyx.h \
	src/libnm-systemd-shared/src/basic/time-util.c \
	src/libnm-systemd-shared/src/basic/time-util.h \
	src/libnm-systemd-shared/src/basic/tmpfile-util.c \
	src/libnm-systemd-shared/src/basic/tmpfile-util.h \
	src/libnm-systemd-shared/src/basic/umask-util.h \
	src/libnm-systemd-shared/src/basic/user-util.h \
	src/libnm-systemd-shared/src/basic/utf8.c \
	src/libnm-systemd-shared/src/basic/utf8.h \
	src/libnm-systemd-shared/src/basic/util.c \
	src/libnm-systemd-shared/src/basic/util.h \
	src/libnm-systemd-shared/src/fundamental/macro-fundamental.h \
	src/libnm-systemd-shared/src/fundamental/sha256.c \
	src/libnm-systemd-shared/src/fundamental/sha256.h \
	src/libnm-systemd-shared/src/fundamental/string-util-fundamental.c \
	src/libnm-systemd-shared/src/fundamental/string-util-fundamental.h \
	src/libnm-systemd-shared/src/shared/dns-domain.c \
	src/libnm-systemd-shared/src/shared/dns-domain.h \
	src/libnm-systemd-shared/src/shared/log-link.h \
	src/libnm-systemd-shared/src/shared/web-util.c \
	src/libnm-systemd-shared/src/shared/web-util.h \
	$(NULL)

src_libnm_systemd_shared_libnm_systemd_shared_la_LIBADD = \
	$(GLIB_LIBS) \
	$(CODE_COVERAGE_LDFLAGS) \
	$(NULL)

EXTRA_DIST += src/libnm-systemd-shared/meson.build

###############################################################################

src_libnm_systemd_core_libnm_systemd_core_la_cppflags = \
	$(libsystemd_cppflags) \
	-I$(srcdir)/src/libnm-systemd-core/sd-adapt-core \
	-I$(srcdir)/src/libnm-systemd-core/src/systemd \
	-I$(srcdir)/src/libnm-systemd-core/src/libsystemd-network \
	-I$(srcdir)/src/libnm-systemd-core/src/libsystemd/sd-event \
	$(NULL)

src_libnm_systemd_core_libnm_systemd_core_la_libadd = \
	$(GLIB_LIBS) \
	$(CODE_COVERAGE_LDFLAGS) \
	$(NULL)

src_libnm_systemd_core_libnm_systemd_core_la_SOURCES = \
	src/libnm-systemd-core/nm-default-systemd-core.h \
	src/libnm-systemd-core/nm-sd.c \
	src/libnm-systemd-core/nm-sd.h \
	src/libnm-systemd-core/sd-adapt-core/condition.h \
	src/libnm-systemd-core/sd-adapt-core/conf-parser.h \
	src/libnm-systemd-core/sd-adapt-core/device-util.h \
	src/libnm-systemd-core/sd-adapt-core/khash.h \
	src/libnm-systemd-core/sd-adapt-core/network-util.h \
	src/libnm-systemd-core/sd-adapt-core/nm-sd-adapt-core.c \
	src/libnm-systemd-core/sd-adapt-core/nm-sd-adapt-core.h \
	src/libnm-systemd-core/sd-adapt-core/sd-daemon.h \
	src/libnm-systemd-core/sd-adapt-core/sd-device.h \
	src/libnm-systemd-core/sd-adapt-core/udev-util.h \
	src/libnm-systemd-core/src/libsystemd-network/dhcp-identifier.c \
	src/libnm-systemd-core/src/libsystemd-network/dhcp-identifier.h \
	src/libnm-systemd-core/src/libsystemd-network/dhcp6-internal.h \
	src/libnm-systemd-core/src/libsystemd-network/dhcp6-lease-internal.h \
	src/libnm-systemd-core/src/libsystemd-network/dhcp6-network.c \
	src/libnm-systemd-core/src/libsystemd-network/dhcp6-option.c \
	src/libnm-systemd-core/src/libsystemd-network/dhcp6-option.h \
	src/libnm-systemd-core/src/libsystemd-network/dhcp6-protocol.c \
	src/libnm-systemd-core/src/libsystemd-network/dhcp6-protocol.h \
	src/libnm-systemd-core/src/libsystemd-network/network-common.c \
	src/libnm-systemd-core/src/libsystemd-network/network-common.h \
	src/libnm-systemd-core/src/libsystemd-network/sd-dhcp6-client.c \
	src/libnm-systemd-core/src/libsystemd-network/sd-dhcp6-lease.c \
	src/libnm-systemd-core/src/libsystemd/sd-event/event-source.h \
	src/libnm-systemd-core/src/libsystemd/sd-event/event-util.c \
	src/libnm-systemd-core/src/libsystemd/sd-event/event-util.h \
	src/libnm-systemd-core/src/libsystemd/sd-event/sd-event.c \
	src/libnm-systemd-core/src/libsystemd/sd-id128/id128-util.c \
	src/libnm-systemd-core/src/libsystemd/sd-id128/id128-util.h \
	src/libnm-systemd-core/src/libsystemd/sd-id128/sd-id128.c \
	src/libnm-systemd-core/src/systemd/_sd-common.h \
	src/libnm-systemd-core/src/systemd/sd-dhcp6-client.h \
	src/libnm-systemd-core/src/systemd/sd-dhcp6-lease.h \
	src/libnm-systemd-core/src/systemd/sd-dhcp6-option.h \
	src/libnm-systemd-core/src/systemd/sd-event.h \
	src/libnm-systemd-core/src/systemd/sd-id128.h \
	src/libnm-systemd-core/src/systemd/sd-ndisc.h \
	$(NULL)

src_libnm_systemd_core_libnm_systemd_core_la_CPPFLAGS = $(src_libnm_systemd_core_libnm_systemd_core_la_cppflags)
src_libnm_systemd_core_libnm_systemd_core_la_LIBADD = \
	$(GLIB_LIBS) \
	$(CODE_COVERAGE_LDFLAGS) \
	$(NULL)
$(src_libnm_systemd_core_libnm_systemd_core_la_OBJECTS): $(src_libnm_core_public_mkenums_h)

EXTRA_DIST += src/libnm-systemd-core/meson.build

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
	src/core/nm-l3-ipv6ll.c \
	src/core/nm-l3-ipv6ll.h \
	src/core/nm-l3cfg.c \
	src/core/nm-l3cfg.h \
	src/core/nm-ip-config.c \
	src/core/nm-ip-config.h \
	src/core/nm-bond-manager.c \
	src/core/nm-bond-manager.h \
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

src_core_libNetworkManagerBase_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBUDEV_LIBS) \
	$(NULL)

$(src_core_libNetworkManagerBase_la_OBJECTS): $(src_libnm_core_public_mkenums_h)

###############################################################################

src_core_libNetworkManager_la_CPPFLAGS = $(src_core_cppflags)

src_core_libNetworkManager_la_SOURCES = \
	\
	src/core/nm-default-daemon.h \
	\
	src/core/nm-checkpoint.c \
	src/core/nm-checkpoint.h \
	src/core/nm-checkpoint-manager.c \
	src/core/nm-checkpoint-manager.h \
	\
	src/core/devices/nm-lldp-listener.c \
	src/core/devices/nm-lldp-listener.h \
	src/core/devices/nm-device-utils.c \
	src/core/devices/nm-device-utils.h \
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
	src/core/devices/nm-device-loopback.c \
	src/core/devices/nm-device-loopback.h \
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
	\
	src/core/dnsmasq/nm-dnsmasq-manager.c \
	src/core/dnsmasq/nm-dnsmasq-manager.h \
	src/core/dnsmasq/nm-dnsmasq-utils.c \
	src/core/dnsmasq/nm-dnsmasq-utils.h \
	\
	src/core/ppp/nm-ppp-mgr.c \
	src/core/ppp/nm-ppp-mgr.h \
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
	src/core/nm-firewall-utils.c \
	src/core/nm-firewall-utils.h \
	src/core/nm-firewalld-manager.c \
	src/core/nm-firewalld-manager.h \
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
	src/core/nm-session-monitor.c \
	src/core/nm-session-monitor.h \
	src/core/nm-priv-helper-call.c \
	src/core/nm-priv-helper-call.h \
	src/core/nm-keep-alive.c \
	src/core/nm-keep-alive.h \
	src/core/nm-sleep-monitor.c \
	src/core/nm-sleep-monitor.h \
	src/core/nm-types.h \
	\
	$(NULL)

src_core_libNetworkManager_la_LIBADD = \
	src/core/libNetworkManagerBase.la \
	src/libnm-core-aux-extern/libnm-core-aux-extern.la \
	src/libnm-core-impl/libnm-core-impl.la \
	src/libnm-crypto/libnm-crypto.la \
	$(libnm_crypto_lib) \
	src/libnm-core-aux-intern/libnm-core-aux-intern.la \
	src/libnm-platform/libnm-platform.la \
	src/libnm-base/libnm-base.la \
	src/libnm-log-core/libnm-log-core.la \
	src/libnm-lldp/libnm-lldp.la \
	src/libnm-udev-aux/libnm-udev-aux.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/libnm-systemd-core/libnm-systemd-core.la \
	src/libnm-systemd-shared/libnm-systemd-shared.la \
	src/n-acd/libn-acd.la \
	src/n-dhcp4/libn-dhcp4.la \
	src/c-rbtree/libc-rbtree.la \
	src/c-siphash/libc-siphash.la \
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

$(src_core_libNetworkManager_la_OBJECTS): $(src_libnm_core_public_mkenums_h)

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
	$(PTHREAD_LIBS) \
	$(NULL)

$(src_core_libNetworkManagerTest_la_OBJECTS): $(src_libnm_core_public_mkenums_h)

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

$(src_core_NetworkManager_all_sym_OBJECTS): $(src_libnm_core_public_mkenums_h)

src/core/NetworkManager.ver: src/core/NetworkManager-all-sym $(core_plugins)
	$(AM_V_GEN) LIBTOOL="$(LIBTOOL)" NM="$(NM)" "$(srcdir)/tools/create-exports-NetworkManager.sh" --called-from-build "$(srcdir)"

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

$(src_core_NetworkManager_OBJECTS): $(src_libnm_core_public_mkenums_h)

###############################################################################

noinst_LTLIBRARIES += src/nm-initrd-generator/libnmi-core.la

src_nm_initrd_generator_libnmi_core_la_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/src/libnm-core-public \
	-I$(builddir)/src/libnm-core-public \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(LIBUDEV_CFLAGS) \
	$(SYSTEMD_JOURNAL_CFLAGS) \
	$(SANITIZER_LIB_CFLAGS) \
	$(NULL)

src_nm_initrd_generator_libnmi_core_la_SOURCES = \
	src/nm-initrd-generator/nm-initrd-generator.h \
	src/nm-initrd-generator/nmi-cmdline-reader.c \
	src/nm-initrd-generator/nmi-dt-reader.c \
	src/nm-initrd-generator/nmi-ibft-reader.c \
	$(NULL)

libexec_PROGRAMS += src/nm-initrd-generator/nm-initrd-generator

src_nm_initrd_generator_nm_initrd_generator_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/src/libnm-core-public \
	-I$(builddir)/src/libnm-core-public \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(CODE_COVERAGE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(LIBUDEV_CFLAGS) \
	$(SYSTEMD_JOURNAL_CFLAGS) \
	$(SANITIZER_EXEC_CFLAGS) \
	$(NULL)

src_nm_initrd_generator_nm_initrd_generator_LDADD = \
	src/nm-initrd-generator/libnmi-core.la \
	src/libnm-core-impl/libnm-core-impl.la \
	src/libnm-crypto/libnm-crypto.la \
	$(libnm_crypto_lib) \
	src/libnm-core-aux-intern/libnm-core-aux-intern.la \
	src/libnm-platform/libnm-platform.la \
	src/libnm-base/libnm-base.la \
	src/libnm-log-core/libnm-log-core.la \
	src/libnm-platform/libnm-platform.la \
	src/libnm-udev-aux/libnm-udev-aux.la \
	src/libnm-systemd-shared/libnm-systemd-shared.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	$(SYSTEMD_JOURNAL_LIBS) \
	$(GLIB_LIBS) \
	$(NULL)

src_nm_initrd_generator_nm_initrd_generator_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

check_programs += src/nm-initrd-generator/tests/test-dt-reader

src_nm_initrd_generator_tests_test_dt_reader_CPPFLAGS = \
	$(src_nm_initrd_generator_nm_initrd_generator_CPPFLAGS)

src_nm_initrd_generator_tests_test_dt_reader_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_nm_initrd_generator_tests_test_dt_reader_LDADD = \
	$(src_nm_initrd_generator_nm_initrd_generator_LDADD)

check_programs += src/nm-initrd-generator/tests/test-ibft-reader

src_nm_initrd_generator_tests_test_ibft_reader_CPPFLAGS = \
	$(src_nm_initrd_generator_nm_initrd_generator_CPPFLAGS)

src_nm_initrd_generator_tests_test_ibft_reader_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_nm_initrd_generator_tests_test_ibft_reader_LDADD = \
	$(src_nm_initrd_generator_nm_initrd_generator_LDADD)

check_programs += src/nm-initrd-generator/tests/test-cmdline-reader

src_nm_initrd_generator_tests_test_cmdline_reader_CPPFLAGS = \
	$(src_nm_initrd_generator_nm_initrd_generator_CPPFLAGS)

src_nm_initrd_generator_tests_test_cmdline_reader_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_nm_initrd_generator_tests_test_cmdline_reader_LDADD = \
	$(src_nm_initrd_generator_nm_initrd_generator_LDADD)

$(src_nm_initrd_generator_libnmi_core_la_OBJECTS):            $(src_libnm_core_public_mkenums_h)
$(src_nm_initrd_generator_nm_initrd_generator_OBJECTS):       $(src_libnm_core_public_mkenums_h)
$(src_nm_initrd_generator_tests_test_cmdline_reader_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_nm_initrd_generator_tests_test_ibft_reader_OBJECTS):    $(src_libnm_core_public_mkenums_h)
$(src_nm_initrd_generator_tests_test_dt_reader_OBJECTS):      $(src_libnm_core_public_mkenums_h)

EXTRA_DIST += \
	src/nm-initrd-generator/meson.build \
	src/nm-initrd-generator/tests/meson.build \
	src/nm-initrd-generator/tests/sysfs/class/net/eth0/address \
	src/nm-initrd-generator/tests/sysfs/class/net/eth2/address \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet0/prefix-len \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet0/hostname \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet0/gateway \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet0/mac \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet0/vlan \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet0/primary-dns \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet0/dhcp \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet0/origin \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet0/secondary-dns \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet0/ip-addr \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet0/subnet-mask \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet0/index \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet0/flags \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/initiator/isns-server \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/initiator/initiator-name \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/initiator/pri-radius-server \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/initiator/slp-server \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/initiator/sec-radius-server \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/initiator/index \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/initiator/flags \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/target0/nic-assoc \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/target0/ip-addr \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/target0/chap-type \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/target0/index \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/target0/lun \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/target0/flags \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/target0/port \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/target2/target-name \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/target2/nic-assoc \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/target2/ip-addr \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/target2/chap-type \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/target2/index \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/target2/lun \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/target2/flags \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/target2/port \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/acpi_header/oem_table_id \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/acpi_header/oem_id \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/acpi_header/signature \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet2/prefix-len \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet2/hostname \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet2/gateway \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet2/mac \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet2/vlan \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet2/primary-dns \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet2/dhcp \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet2/origin \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet2/secondary-dns \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet2/ip-addr \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet2/subnet-mask \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet2/index \
	src/nm-initrd-generator/tests/sysfs/firmware/ibft/ethernet2/flags \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/class/net/eth0/address \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/prefix-len \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/gateway \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/mac \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/vlan \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/primary-dns \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/origin \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/secondary-dns \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/ip-addr \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/subnet-mask \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/firmware/ibft/ethernet0/index \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/firmware/ibft/initiator/initiator-name \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/firmware/ibft/target0/target-name \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/firmware/ibft/target0/ip-addr \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/firmware/ibft/target0/index \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/firmware/ibft/target0/lun \
	src/nm-initrd-generator/tests/sysfs-bad-dns1/firmware/ibft/target0/port \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/class/net/eth0/address \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/prefix-len \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/gateway \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/mac \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/vlan \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/primary-dns \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/origin \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/secondary-dns \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/ip-addr \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/subnet-mask \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/firmware/ibft/ethernet0/index \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/firmware/ibft/initiator/initiator-name \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/firmware/ibft/target0/target-name \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/firmware/ibft/target0/ip-addr \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/firmware/ibft/target0/index \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/firmware/ibft/target0/lun \
	src/nm-initrd-generator/tests/sysfs-bad-dns2/firmware/ibft/target0/port \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/class/net/eth0/address \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/prefix-len \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/gateway \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/mac \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/vlan \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/primary-dns \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/origin \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/secondary-dns \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/ip-addr \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/subnet-mask \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/firmware/ibft/ethernet0/index \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/firmware/ibft/initiator/initiator-name \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/firmware/ibft/target0/target-name \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/firmware/ibft/target0/ip-addr \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/firmware/ibft/target0/index \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/firmware/ibft/target0/lun \
	src/nm-initrd-generator/tests/sysfs-bad-gateway/firmware/ibft/target0/port \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/class/net/eth0/address \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/prefix-len \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/gateway \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/mac \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/vlan \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/primary-dns \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/origin \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/secondary-dns \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/ip-addr \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/subnet-mask \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/firmware/ibft/ethernet0/index \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/firmware/ibft/initiator/initiator-name \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/firmware/ibft/target0/target-name \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/firmware/ibft/target0/ip-addr \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/firmware/ibft/target0/index \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/firmware/ibft/target0/lun \
	src/nm-initrd-generator/tests/sysfs-bad-ipaddr/firmware/ibft/target0/port \
	src/nm-initrd-generator/tests/sysfs-dhcp/class/net/eth0/address \
	src/nm-initrd-generator/tests/sysfs-dhcp/class/net/eth1/address \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/ethernet0/gateway \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/ethernet0/mac \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/ethernet0/vlan \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/ethernet0/primary-dns \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/ethernet0/origin \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/ethernet0/secondary-dns \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/ethernet0/index \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/initiator/initiator-name \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/target0/target-name \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/target0/ip-addr \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/target0/index \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/target0/lun \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/target0/port \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/ethernet1/gateway \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/ethernet1/mac \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/ethernet1/vlan \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/ethernet1/primary-dns \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/ethernet1/origin \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/ethernet1/secondary-dns \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/ethernet1/index \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/target1/target-name \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/target1/ip-addr \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/target1/index \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/target1/lun \
	src/nm-initrd-generator/tests/sysfs-dhcp/firmware/ibft/target1/port \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/chosen/bootpath \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/chosen/bootp-request \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/chosen/bootp-response \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/chosen/broadcast-ip \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/chosen/client-ip \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/chosen/client-name \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/chosen/domain-name \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/chosen/gateway-ip \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/chosen/name \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/chosen/netmask-ip \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/chosen/root-path \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/chosen/server-ip \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/chosen/tftp-file \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/chosen/vendor-options \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/ethernet/device_type \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/ethernet/local-mac-address \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/ethernet/mac-address \
	src/nm-initrd-generator/tests/sysfs-dt/firmware/devicetree/base/ethernet/name \
	src/nm-initrd-generator/tests/sysfs-dt-tftp/firmware/devicetree/base/chosen/bootpath \
	src/nm-initrd-generator/tests/sysfs-static/class/net/eth0/address \
	src/nm-initrd-generator/tests/sysfs-static/class/net/eth1/address \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet0/prefix-len \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet0/gateway \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet0/mac \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet0/vlan \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet0/primary-dns \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet0/origin \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet0/secondary-dns \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet0/ip-addr \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet0/subnet-mask \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet0/index \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/initiator/initiator-name \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/target0/target-name \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/target0/ip-addr \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/target0/index \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/target0/lun \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/target0/port \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet1/gateway \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet1/mac \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet1/vlan \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet1/primary-dns \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet1/origin \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet1/secondary-dns \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/ethernet1/index \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/target1/target-name \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/target1/ip-addr \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/target1/index \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/target1/lun \
	src/nm-initrd-generator/tests/sysfs-static/firmware/ibft/target1/port \
	src/nm-initrd-generator/tests/sysfs-vlan/class/net/eth0/address \
	src/nm-initrd-generator/tests/sysfs-vlan/firmware/ibft/ethernet0/prefix-len \
	src/nm-initrd-generator/tests/sysfs-vlan/firmware/ibft/ethernet0/mac \
	src/nm-initrd-generator/tests/sysfs-vlan/firmware/ibft/ethernet0/vlan \
	src/nm-initrd-generator/tests/sysfs-vlan/firmware/ibft/ethernet0/origin \
	src/nm-initrd-generator/tests/sysfs-vlan/firmware/ibft/ethernet0/ip-addr \
	src/nm-initrd-generator/tests/sysfs-vlan/firmware/ibft/ethernet0/subnet-mask \
	src/nm-initrd-generator/tests/sysfs-vlan/firmware/ibft/ethernet0/index \
	src/nm-initrd-generator/tests/sysfs-vlan/firmware/ibft/initiator/initiator-name \
	src/nm-initrd-generator/tests/sysfs-vlan/firmware/ibft/target0/target-name \
	src/nm-initrd-generator/tests/sysfs-vlan/firmware/ibft/target0/ip-addr \
	src/nm-initrd-generator/tests/sysfs-vlan/firmware/ibft/target0/index \
	src/nm-initrd-generator/tests/sysfs-vlan/firmware/ibft/target0/lun \
	src/nm-initrd-generator/tests/sysfs-vlan/firmware/ibft/target0/port \
	$(NULL)

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
	-I$(srcdir)/src \
	-I$(builddir)/src \
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

$(src_core_dhcp_tests_test_dhcp_dhclient_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_core_dhcp_tests_test_dhcp_utils_OBJECTS): $(src_libnm_core_public_mkenums_h)

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
	-I$(srcdir)/src \
	-I$(builddir)/src \
	-I$(builddir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-core-public \
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

$(src_core_ppp_nm_pppd_plugin_la_OBJECTS): $(src_libnm_core_public_mkenums_h)

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

$(src_core_ppp_libnm_ppp_plugin_la_OBJECTS): $(src_libnm_core_public_mkenums_h)

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

$(src_core_settings_plugins_keyfile_tests_test_keyfile_settings_OBJECTS): $(src_libnm_core_public_mkenums_h)

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

$(src_core_settings_plugins_ifcfg_rh_libnms_ifcfg_rh_core_la_OBJECTS): $(src_libnm_core_public_mkenums_h)

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
$(src_core_settings_plugins_ifcfg_rh_libnm_settings_plugin_ifcfg_rh_la_OBJECTS): $(src_libnm_core_public_mkenums_h)

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

$(src_core_settings_plugins_ifcfg_rh_tests_test_ifcfg_rh_OBJECTS): $(src_libnm_core_public_mkenums_h)

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
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-bond-port \
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
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-ipoib \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-link_local \
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
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-tc-write-empty.cexpected \
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
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-vlanid-use \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-vlan-vlanid-use.cexpected \
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
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-eap-suite-b-192-tls \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-eap-tls \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test-wifi-wpa-eap-ttls-tls \
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
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test_roundtrip_ethtool-1.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test_roundtrip_ethtool-2.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test_roundtrip_ethtool-3.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test_roundtrip_ethtool-4.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test_roundtrip_ethtool-5.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test_roundtrip_ethtool-6.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test_roundtrip_ethtool-7.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test_roundtrip_ethtool-8.cexpected \
	src/core/settings/plugins/ifcfg-rh/tests/network-scripts/ifcfg-test_roundtrip_ethtool-9.cexpected \
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

$(src_core_settings_plugins_ifupdown_libnm_settings_plugin_ifupdown_la_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_core_settings_plugins_ifupdown_libnms_ifupdown_core_la_OBJECTS): $(src_libnm_core_public_mkenums_h)

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

$(src_core_settings_plugins_ifupdown_tests_test_ifupdown_OBJECTS): $(src_libnm_core_public_mkenums_h)

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

$(src_core_devices_wwan_libnm_wwan_la_OBJECTS): $(src_libnm_core_public_mkenums_h)

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

$(src_core_devices_wwan_tests_test_service_providers_OBJECTS): $(src_libnm_core_public_mkenums_h)

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

$(src_core_devices_bluetooth_libnm_bluetooth_utils_la_OBJECTS): $(src_libnm_core_public_mkenums_h)

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

$(src_core_devices_bluetooth_tests_nm_bt_test_OBJECTS): $(src_libnm_core_public_mkenums_h)

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
	src/core/devices/wifi/nm-device-iwd-p2p.c \
	src/core/devices/wifi/nm-device-iwd-p2p.h \
	src/core/devices/wifi/nm-iwd-manager.c \
	src/core/devices/wifi/nm-iwd-manager.h \
	$(NULL)
endif

src_core_devices_wifi_libnm_wifi_base_la_CPPFLAGS = $(src_core_cppflags_device_plugin)

src_core_devices_wifi_libnm_wifi_base_la_LIBADD = \
	$(GLIB_LIBS)

$(src_core_devices_wifi_libnm_wifi_base_la_OBJECTS): $(src_libnm_core_public_mkenums_h)

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

$(src_core_devices_wifi_tests_test_devices_wifi_OBJECTS): $(src_libnm_core_public_mkenums_h)

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

check_local += check-local-devices-ovs

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

$(src_core_dnsmasq_tests_test_dnsmasq_utils_OBJECTS): $(src_libnm_core_public_mkenums_h)

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

src_core_platform_tests_test_tc_linux_SOURCES = src/core/platform/tests/test-tc.c
src_core_platform_tests_test_tc_linux_CPPFLAGS = $(src_core_tests_cppflags_linux)
src_core_platform_tests_test_tc_linux_LDFLAGS = $(src_core_platform_tests_ldflags)
src_core_platform_tests_test_tc_linux_LDADD = $(src_core_platform_tests_libadd)


$(src_core_platform_tests_monitor_OBJECTS):               $(src_libnm_core_public_mkenums_h)
$(src_core_platform_tests_test_address_fake_OBJECTS):     $(src_libnm_core_public_mkenums_h)
$(src_core_platform_tests_test_address_linux_OBJECTS):    $(src_libnm_core_public_mkenums_h)
$(src_core_platform_tests_test_cleanup_fake_OBJECTS):     $(src_libnm_core_public_mkenums_h)
$(src_core_platform_tests_test_cleanup_linux_OBJECTS):    $(src_libnm_core_public_mkenums_h)
$(src_core_platform_tests_test_link_fake_OBJECTS):        $(src_libnm_core_public_mkenums_h)
$(src_core_platform_tests_test_link_linux_OBJECTS):       $(src_libnm_core_public_mkenums_h)
$(src_core_platform_tests_test_nmp_object_OBJECTS):       $(src_libnm_core_public_mkenums_h)
$(src_core_platform_tests_test_platform_general_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_core_platform_tests_test_route_fake_OBJECTS):       $(src_libnm_core_public_mkenums_h)
$(src_core_platform_tests_test_route_linux_OBJECTS):      $(src_libnm_core_public_mkenums_h)
$(src_core_platform_tests_test_tc_fake_OBJECTS):          $(src_libnm_core_public_mkenums_h)
$(src_core_platform_tests_test_tc_linux_OBJECTS):         $(src_libnm_core_public_mkenums_h)

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
	$(NULL)

src_core_devices_tests_test_lldp_CPPFLAGS = $(src_core_cppflags_test)
src_core_devices_tests_test_lldp_LDFLAGS = $(src_core_devices_tests_ldflags)
src_core_devices_tests_test_lldp_LDADD = \
	src/core/libNetworkManagerTest.la

$(src_core_devices_tests_test_lldp_OBJECTS): $(src_libnm_core_public_mkenums_h)

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

$(src_core_ndisc_tests_test_ndisc_linux_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_core_ndisc_tests_test_ndisc_fake_OBJECTS): $(src_libnm_core_public_mkenums_h)

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

$(src_core_supplicant_tests_test_supplicant_config_OBJECTS): $(src_libnm_core_public_mkenums_h)

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

$(src_core_tests_config_test_config_OBJECTS): $(src_libnm_core_public_mkenums_h)

EXTRA_DIST += \
	src/core/tests/config/NetworkManager.conf \
	src/core/tests/config/NetworkManager-warn.conf \
	src/core/tests/config/NetworkManager.state \
	src/core/tests/config/bad.conf \
	src/core/tests/config/global-dns-good.conf \
	src/core/tests/config/global-dns-invalid.conf \
	src/core/tests/config/global-dns-options.conf \
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
	src/core/tests/test-l3cfg \
	src/core/tests/test-systemd \
	src/core/tests/test-utils \
	src/core/tests/test-wired-defname \
	$(NULL)

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

$(src_core_tests_test_core_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_core_tests_test_core_with_expect_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_core_tests_test_dcb_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_core_tests_test_l3cfg_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_core_tests_test_utils_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_core_tests_test_wired_defname_OBJECTS): $(src_libnm_core_public_mkenums_h)

src_core_tests_test_systemd_CPPFLAGS = \
	$(src_libnm_systemd_core_libnm_systemd_core_la_cppflags) \
	$(NULL)

src_core_tests_test_systemd_LDFLAGS = \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_core_tests_test_systemd_LDADD = \
	src/libnm-systemd-core/libnm-systemd-core.la \
	src/libnm-systemd-shared/libnm-systemd-shared.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	$(GLIB_LIBS) \
	$(CODE_COVERAGE_LDFLAGS) \
	$(NULL)

$(src_core_tests_test_systemd_OBJECTS): $(src_libnm_core_public_mkenums_h)

EXTRA_DIST += \
	src/core/tests/test-secret-agent.py \
	src/core/tests/meson.build

###############################################################################
# src/nm-dispatcher
###############################################################################

dispatcher_nmdbus_dispatcher_sources = \
	src/nm-dispatcher/nmdbus-dispatcher.h \
	src/nm-dispatcher/nmdbus-dispatcher.c \
	$(NULL)

src/nm-dispatcher/nmdbus-dispatcher.h: src/nm-dispatcher/nm-dispatcher.xml
	@$(MKDIR_P) src/nm-dispatcher/
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--c-namespace NMDBus \
		--interface-prefix org.freedesktop \
		$<

src/nm-dispatcher/nmdbus-dispatcher.c: src/nm-dispatcher/nmdbus-dispatcher.h

CLEANFILES += $(dispatcher_nmdbus_dispatcher_sources)

###############################################################################

libexec_PROGRAMS += src/nm-dispatcher/nm-dispatcher

noinst_LTLIBRARIES += src/nm-dispatcher/libnm-dispatcher-core.la

dispatcher_cppflags = \
	$(dflt_cppflags) \
	-I$(builddir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-core-public \
	-I$(builddir)/src/libnm-client-public \
	-I$(srcdir)/src/libnm-client-public \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(GLIB_CFLAGS) \
	$(NULL)

src_nm_dispatcher_libnm_dispatcher_core_la_SOURCES = \
	src/nm-dispatcher/nm-dispatcher-utils.c \
	src/nm-dispatcher/nm-dispatcher-utils.h \
	$(NULL)

src_nm_dispatcher_libnm_dispatcher_core_la_CPPFLAGS = $(dispatcher_cppflags)

src_nm_dispatcher_libnm_dispatcher_core_la_LIBADD = \
	src/libnm-client-impl/libnm.la \
	$(GLIB_LIBS)

src_nm_dispatcher_nm_dispatcher_SOURCES = \
	src/nm-dispatcher/nm-dispatcher.c \
	$(NULL)

src_nm_dispatcher_nm_dispatcher_CPPFLAGS = $(dispatcher_cppflags)

src_nm_dispatcher_nm_dispatcher_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_nm_dispatcher_nm_dispatcher_LDADD = \
	src/nm-dispatcher/libnm-dispatcher-core.la \
	src/libnm-client-impl/libnm.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	$(GLIB_LIBS) \
	$(NULL)

src/nm-dispatcher/org.freedesktop.nm_dispatcher.service: $(srcdir)/src/nm-dispatcher/org.freedesktop.nm_dispatcher.service.in
	@sed \
	-e 's|@sbindir[@]|$(sbindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g' \
	-e 's|@libexecdir[@]|$(libexecdir)|g' \
	$< >$@

dbusactivation_DATA += src/nm-dispatcher/org.freedesktop.nm_dispatcher.service
CLEANFILES += src/nm-dispatcher/org.freedesktop.nm_dispatcher.service

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

dbusservice_DATA += src/nm-dispatcher/nm-dispatcher.conf

EXTRA_DIST += \
	src/nm-dispatcher/nm-dispatcher.conf \
	src/nm-dispatcher/org.freedesktop.nm_dispatcher.service.in \
	src/nm-dispatcher/nm-dispatcher.xml \
	src/nm-dispatcher/meson.build \
	$(NULL)

###############################################################################
# src/nm-dispatcher/tests
###############################################################################

check_programs += src/nm-dispatcher/tests/test-dispatcher-envp

src_nm_dispatcher_tests_test_dispatcher_envp_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(builddir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-client-public \
	-I$(builddir)/src/libnm-client-public \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(GLIB_CFLAGS) \
	$(SANITIZER_EXEC_CFLAGS) \
	$(INTROSPECTION_EXTRA_CFLAGS) \
	$(NULL)

src_nm_dispatcher_tests_test_dispatcher_envp_SOURCES = \
	src/nm-dispatcher/tests/test-dispatcher-envp.c \
	$(NULL)

nodist_src_nm_dispatcher_tests_test_dispatcher_envp_SOURCES = $(dispatcher_nmdbus_dispatcher_sources)

$(src_nm_dispatcher_tests_test_dispatcher_envp_OBJECTS): $(dispatcher_nmdbus_dispatcher_sources)
$(src_nm_dispatcher_tests_test_dispatcher_envp_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_nm_dispatcher_tests_test_dispatcher_envp_OBJECTS): $(src_libnm_client_public_mkenums_h)

src_nm_dispatcher_tests_test_dispatcher_envp_LDFLAGS = \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_nm_dispatcher_tests_test_dispatcher_envp_LDADD = \
	src/nm-dispatcher/libnm-dispatcher-core.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	src/libnm-client-impl/libnm.la \
	$(GLIB_LIBS) \
	$(NULL)

$(src_nm_dispatcher_tests_test_dispatcher_envp_OBJECTS): $(src_libnm_core_public_mkenums_h)

EXTRA_DIST += \
	src/nm-dispatcher/tests/dispatcher-connectivity-full \
	src/nm-dispatcher/tests/dispatcher-connectivity-unknown \
	src/nm-dispatcher/tests/dispatcher-down \
	src/nm-dispatcher/tests/dispatcher-external \
	src/nm-dispatcher/tests/dispatcher-up \
	src/nm-dispatcher/tests/dispatcher-vpn-down \
	src/nm-dispatcher/tests/dispatcher-vpn-up \
	src/nm-dispatcher/tests/meson.build \
	$(NULL)

###############################################################################
# src/nm-priv-helper
###############################################################################

libexec_PROGRAMS += src/nm-priv-helper/nm-priv-helper

src_nm_priv_helper_nm_priv_helper_SOURCES = \
	src/nm-priv-helper/nm-priv-helper.c \
	$(NULL)

src_nm_priv_helper_nm_priv_helper_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(builddir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-core-public \
	-I$(builddir)/src/libnm-client-public \
	-I$(srcdir)/src/libnm-client-public \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(GLIB_CFLAGS) \
	$(NULL)

src_nm_priv_helper_nm_priv_helper_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_nm_priv_helper_nm_priv_helper_LDADD = \
	src/libnm-base/libnm-base.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	$(GLIB_LIBS) \
	$(NULL)

src/nm-priv-helper/org.freedesktop.nm_priv_helper.service: $(srcdir)/src/nm-priv-helper/org.freedesktop.nm_priv_helper.service.in
	@sed \
	-e 's|@libexecdir[@]|$(libexecdir)|g' \
	$< >$@

dbusactivation_DATA += src/nm-priv-helper/org.freedesktop.nm_priv_helper.service
CLEANFILES += src/nm-priv-helper/org.freedesktop.nm_priv_helper.service

dbusservice_DATA += src/nm-priv-helper/nm-priv-helper.conf

EXTRA_DIST += \
	src/nm-priv-helper/nm-priv-helper.conf \
	src/nm-priv-helper/org.freedesktop.nm_priv_helper.service.in \
	src/nm-priv-helper/meson.build \
	$(NULL)

###############################################################################
# src/nm-daemon-helper
###############################################################################

libexec_PROGRAMS += src/nm-daemon-helper/nm-daemon-helper

src_nm_daemon_helper_nm_daemon_helper_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	$(NULL)

src_nm_daemon_helper_nm_daemon_helper_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_nm_daemon_helper_nm_daemon_helper_LDADD = \
	src/libnm-std-aux/libnm-std-aux.la \
	$(NULL)

EXTRA_DIST += \
	src/nm-daemon-helper/meson.build \
	$(NULL)

###############################################################################
# src/nm-online
###############################################################################

bin_PROGRAMS += src/nm-online/nm-online

src_nm_online_nm_online_CPPFLAGS = \
	$(dflt_cppflags) \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	-I$(builddir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-client-public \
	-I$(builddir)/src/libnm-client-public \
	$(GLIB_CFLAGS) \
	$(NULL)

src_nm_online_nm_online_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_nm_online_nm_online_LDADD = \
	src/libnm-client-impl/libnm.la \
	src/libnm-client-aux-extern/libnm-client-aux-extern.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	$(GLIB_LIBS) \
	$(NULL)

$(src_nm_online_nm_online_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_nm_online_nm_online_OBJECTS): $(src_libnm_client_public_mkenums_h)

EXTRA_DIST += src/nm-online/meson.build

###############################################################################
# src/libnmc-base
###############################################################################

clients_cppflags = \
	$(dflt_cppflags) \
	-I$(srcdir)/src \
	-I$(builddir)/src \
	-I$(srcdir)/src/libnm-core-public \
	-I$(builddir)/src/libnm-core-public \
	-I$(srcdir)/src/libnm-client-public \
	-I$(builddir)/src/libnm-client-public \
	$(GLIB_CFLAGS) \
	$(SANITIZER_EXEC_CFLAGS) \
	$(NULL)

check_ltlibraries += src/libnmc-base/libnmc-base.la

src_libnmc_base_libnmc_base_la_SOURCES = \
	src/libnmc-base/nm-client-utils.c \
	src/libnmc-base/nm-client-utils.h \
	src/libnmc-base/nm-polkit-listener.c \
	src/libnmc-base/nm-polkit-listener.h \
	src/libnmc-base/nm-secret-agent-simple.c \
	src/libnmc-base/nm-secret-agent-simple.h \
	src/libnmc-base/nm-vpn-helpers.c \
	src/libnmc-base/nm-vpn-helpers.h \
	$(NULL)

EXTRA_DIST += \
	src/libnmc-base/qrcodegen.c \
	src/libnmc-base/qrcodegen.h \
	$(NULL)

src_libnmc_base_libnmc_base_la_CPPFLAGS = \
	$(clients_cppflags) \
	$(NULL)

src_libnmc_base_libnmc_base_la_LIBADD = \
	src/libnm-client-impl/libnm.la \
	$(GLIB_LIBS) \
	$(NULL)

$(src_libnmc_base_libnmc_base_la_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_libnmc_base_libnmc_base_la_OBJECTS): $(src_libnm_client_public_mkenums_h)

EXTRA_DIST += src/libnmc-base/meson.build

###############################################################################
# src/libnmc-setting
###############################################################################

libnmc_setting_settings_doc_h = src/libnmc-setting/settings-docs.h
if BUILD_DOCS
$(libnmc_setting_settings_doc_h): src/libnmc-setting/settings-docs-input.xml src/libnmc-setting/.dirstamp tools/generate-docs-settings-docs.py
	$(AM_V_GEN) "$(PYTHON)" $(srcdir)/tools/generate-docs-settings-docs.py --output $@ --xml $<
DISTCLEANFILES += $(libnmc_setting_settings_doc_h)
check-local-settings-docs: $(libnmc_setting_settings_doc_h)
	$(srcdir)/tools/check-compare-generated.sh "$(srcdir)/$(libnmc_setting_settings_doc_h).in" "$(builddir)/$(libnmc_setting_settings_doc_h)"
check_local += check-local-settings-docs
else
$(libnmc_setting_settings_doc_h): $(libnmc_setting_settings_doc_h).in src/libnmc-setting/.dirstamp
	$(AM_V_GEN) cp "$(srcdir)/$(libnmc_setting_settings_doc_h).in" "$(builddir)/$(libnmc_setting_settings_doc_h)"
check-local-settings-docs:
endif
EXTRA_DIST += \
	tools/generate-docs-settings-docs.py \
	$(libnmc_setting_settings_doc_h) \
	$(libnmc_setting_settings_doc_h).in

check_ltlibraries += src/libnmc-setting/libnmc-setting.la

src_libnmc_setting_libnmc_setting_la_SOURCES = \
	src/libnmc-setting/nm-meta-setting-access.c \
	src/libnmc-setting/nm-meta-setting-access.h \
	src/libnmc-setting/nm-meta-setting-base-impl.c \
	src/libnmc-setting/nm-meta-setting-base-impl.h \
	src/libnmc-setting/nm-meta-setting-base.h \
	src/libnmc-setting/nm-meta-setting-desc.c \
	src/libnmc-setting/nm-meta-setting-desc.h \
	$(NULL)

src_libnmc_setting_libnmc_setting_la_CPPFLAGS = \
	$(clients_cppflags) \
	$(NULL)

src_libnmc_setting_libnmc_setting_la_LIBADD = \
	src/libnm-client-impl/libnm.la \
	$(GLIB_LIBS) \
	$(NULL)

$(src_libnmc_setting_libnmc_setting_la_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_libnmc_setting_libnmc_setting_la_OBJECTS): $(src_libnm_client_public_mkenums_h)
$(src_libnmc_setting_libnmc_setting_la_OBJECTS): $(libnmc_setting_settings_doc_h)
$(src_libnmc_setting_libnmc_setting_la_OBJECTS): src/libnmc-setting/.dirstamp

###############################################################################

check_programs += src/libnmc-setting/tests/test-libnmc-setting

src_libnmc_setting_tests_test_libnmc_setting_CPPFLAGS = \
	$(clients_cppflags) \
	$(NULL)

src_libnmc_setting_tests_test_libnmc_setting_LDFLAGS = \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_libnmc_setting_tests_test_libnmc_setting_LDADD = \
	src/libnmc-setting/libnmc-setting.la \
	src/libnmc-base/libnmc-base.la \
	src/libnm-core-aux-extern/libnm-core-aux-extern.la \
	src/libnm-core-aux-intern/libnm-core-aux-intern.la \
	src/libnm-base/libnm-base.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	src/libnm-client-impl/libnm.la \
	$(GLIB_LIBS)

$(src_libnmc_setting_tests_test_libnmc_setting_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_libnmc_setting_tests_test_libnmc_setting_OBJECTS): $(src_libnm_client_public_mkenums_h)

EXTRA_DIST += \
	src/libnmc-setting/tests/wg-test0.conf \
	src/libnmc-setting/tests/wg-test1.conf \
	src/libnmc-setting/tests/wg-test2.conf \
	src/libnmc-setting/tests/wg-test3.conf \
	$(NULL)

###############################################################################
# src/nmcli
###############################################################################

if BUILD_NMCLI

bin_PROGRAMS += src/nmcli/nmcli

src_nmcli_nmcli_SOURCES = \
	src/nmcli/common.c \
	src/nmcli/common.h \
	src/nmcli/utils.c \
	src/nmcli/utils.h \
	src/nmcli/agent.c \
	src/nmcli/general.c \
	src/nmcli/connections.c \
	src/nmcli/connections.h \
	src/nmcli/devices.c \
	src/nmcli/devices.h \
	src/nmcli/settings.c \
	src/nmcli/settings.h \
	src/nmcli/nmcli.c \
	src/nmcli/nmcli.h \
	src/nmcli/polkit-agent.c \
	src/nmcli/polkit-agent.h \
	$(NULL)

src_nmcli_nmcli_CPPFLAGS = \
	$(clients_cppflags) \
	$(NULL)

src_nmcli_nmcli_LDADD = \
	src/libnmc-setting/libnmc-setting.la \
	src/libnmc-base/libnmc-base.la \
	src/libnm-core-aux-extern/libnm-core-aux-extern.la \
	src/libnm-core-aux-intern/libnm-core-aux-intern.la \
	src/libnm-base/libnm-base.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	src/libnm-client-aux-extern/libnm-client-aux-extern.la \
	src/libnm-client-impl/libnm.la \
	$(GLIB_LIBS) \
	$(READLINE_LIBS)

src_nmcli_nmcli_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS)

$(src_nmcli_nmcli_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_nmcli_nmcli_OBJECTS): $(src_libnm_client_public_mkenums_h)

install-data-hook-nmcli:
	$(mkinstalldirs) $(DESTDIR)$(completiondir)
	$(INSTALL_DATA) $(srcdir)/src/nmcli/nmcli-completion $(DESTDIR)$(completiondir)/nmcli

install_data_hook += install-data-hook-nmcli

uninstall-hook-nmcli:
	rm -f $(DESTDIR)$(completiondir)/nmcli

uninstall_hook += uninstall-hook-nmcli

endif

###############################################################################

noinst_PROGRAMS += src/nmcli/gen-metadata-nm-settings-nmcli

src_nmcli_gen_metadata_nm_settings_nmcli_SOURCES = \
	src/nmcli/gen-metadata-nm-settings-nmcli.c \
	$(NULL)

src_nmcli_gen_metadata_nm_settings_nmcli_CPPFLAGS = \
	$(clients_cppflags) \
	$(NULL)

src_nmcli_gen_metadata_nm_settings_nmcli_LDADD = \
	src/libnmc-setting/libnmc-setting.la \
	src/libnmc-base/libnmc-base.la \
	src/libnm-client-aux-extern/libnm-client-aux-extern.la \
	src/libnm-core-aux-extern/libnm-core-aux-extern.la \
	src/libnm-core-aux-intern/libnm-core-aux-intern.la \
	src/libnm-base/libnm-base.la \
	src/libnm-client-impl/libnm.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	$(GLIB_LIBS) \
	$(NULL)

src_nmcli_gen_metadata_nm_settings_nmcli_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

$(src_nmcli_gen_metadata_nm_settings_nmcli_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_nmcli_gen_metadata_nm_settings_nmcli_OBJECTS): $(src_libnm_client_public_mkenums_h)

###############################################################################

EXTRA_DIST += \
	src/nmcli/nmcli-completion \
	src/nmcli/meson.build \
	src/libnmc-setting/meson.build \
	src/libnmc-setting/tests/meson.build

###############################################################################
# src/libnmt-newt
###############################################################################

if BUILD_NMTUI

noinst_LIBRARIES += src/libnmt-newt/libnmt-newt.a

src_libnmt_newt_libnmt_newt_a_SOURCES = \
	src/libnmt-newt/nmt-newt-button-box.c \
	src/libnmt-newt/nmt-newt-button-box.h \
	src/libnmt-newt/nmt-newt-button.c \
	src/libnmt-newt/nmt-newt-button.h \
	src/libnmt-newt/nmt-newt-checkbox.c \
	src/libnmt-newt/nmt-newt-checkbox.h \
	src/libnmt-newt/nmt-newt-component.c \
	src/libnmt-newt/nmt-newt-component.h \
	src/libnmt-newt/nmt-newt-container.c \
	src/libnmt-newt/nmt-newt-container.h \
	src/libnmt-newt/nmt-newt-entry-numeric.c \
	src/libnmt-newt/nmt-newt-entry-numeric.h \
	src/libnmt-newt/nmt-newt-entry.c \
	src/libnmt-newt/nmt-newt-entry.h \
	src/libnmt-newt/nmt-newt-form.c \
	src/libnmt-newt/nmt-newt-form.h \
	src/libnmt-newt/nmt-newt-grid.c \
	src/libnmt-newt/nmt-newt-grid.h \
	src/libnmt-newt/nmt-newt-hacks.c \
	src/libnmt-newt/nmt-newt-hacks.h \
	src/libnmt-newt/nmt-newt-label.c \
	src/libnmt-newt/nmt-newt-label.h \
	src/libnmt-newt/nmt-newt-listbox.c \
	src/libnmt-newt/nmt-newt-listbox.h \
	src/libnmt-newt/nmt-newt-popup.c \
	src/libnmt-newt/nmt-newt-popup.h \
	src/libnmt-newt/nmt-newt-section.c \
	src/libnmt-newt/nmt-newt-section.h \
	src/libnmt-newt/nmt-newt-separator.c \
	src/libnmt-newt/nmt-newt-separator.h \
	src/libnmt-newt/nmt-newt-stack.c \
	src/libnmt-newt/nmt-newt-stack.h \
	src/libnmt-newt/nmt-newt-textbox.c \
	src/libnmt-newt/nmt-newt-textbox.h \
	src/libnmt-newt/nmt-newt-toggle-button.c \
	src/libnmt-newt/nmt-newt-toggle-button.h \
	src/libnmt-newt/nmt-newt-types.h \
	src/libnmt-newt/nmt-newt-utils.c \
	src/libnmt-newt/nmt-newt-utils.h \
	src/libnmt-newt/nmt-newt-widget.c \
	src/libnmt-newt/nmt-newt-widget.h \
	src/libnmt-newt/nmt-newt.h \
	$(NULL)

src_libnmt_newt_libnmt_newt_a_CPPFLAGS = \
	$(clients_cppflags) \
	$(NEWT_CFLAGS) \
	$(NULL)

$(src_libnmt_newt_libnmt_newt_a_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_libnmt_newt_libnmt_newt_a_OBJECTS): $(src_libnm_client_public_mkenums_h)

endif

EXTRA_DIST += src/libnmt-newt/meson.build

###############################################################################
# src/nmtui
###############################################################################

if BUILD_NMTUI

bin_PROGRAMS += src/nmtui/nmtui

src_nmtui_nmtui_SOURCES = \
	src/nmtui/nmtui.c \
	src/nmtui/nmtui.h \
	src/nmtui/nmtui-connect.c \
	src/nmtui/nmtui-connect.h \
	src/nmtui/nmtui-edit.c \
	src/nmtui/nmtui-edit.h \
	src/nmtui/nmtui-hostname.c \
	src/nmtui/nmtui-hostname.h \
	\
	src/nmtui/nm-editor-bindings.c \
	src/nmtui/nm-editor-bindings.h \
	src/nmtui/nm-editor-utils.c \
	src/nmtui/nm-editor-utils.h \
	\
	src/nmtui/nmt-8021x-fields.c \
	src/nmtui/nmt-8021x-fields.h \
	src/nmtui/nmt-address-list.c \
	src/nmtui/nmt-address-list.h \
	src/nmtui/nmt-connect-connection-list.c \
	src/nmtui/nmt-connect-connection-list.h \
	src/nmtui/nmt-device-entry.c \
	src/nmtui/nmt-device-entry.h \
	src/nmtui/nmt-edit-connection-list.c \
	src/nmtui/nmt-edit-connection-list.h \
	src/nmtui/nmt-editor-grid.c \
	src/nmtui/nmt-editor-grid.h \
	src/nmtui/nmt-editor-page-device.c \
	src/nmtui/nmt-editor-page-device.h \
	src/nmtui/nmt-editor-page.c \
	src/nmtui/nmt-editor-page.h \
	src/nmtui/nmt-editor-section.c \
	src/nmtui/nmt-editor-section.h \
	src/nmtui/nmt-editor.c \
	src/nmtui/nmt-editor.h \
	src/nmtui/nmt-ip-entry.c \
	src/nmtui/nmt-ip-entry.h \
	src/nmtui/nmt-mac-entry.c \
	src/nmtui/nmt-mac-entry.h \
	src/nmtui/nmt-mtu-entry.c \
	src/nmtui/nmt-mtu-entry.h \
	src/nmtui/nmt-page-bond-port.c \
	src/nmtui/nmt-page-bond-port.h \
	src/nmtui/nmt-page-bond.c \
	src/nmtui/nmt-page-bond.h \
	src/nmtui/nmt-page-bridge-port.c \
	src/nmtui/nmt-page-bridge-port.h \
	src/nmtui/nmt-page-bridge.c \
	src/nmtui/nmt-page-bridge.h \
	src/nmtui/nmt-page-dsl.c \
	src/nmtui/nmt-page-dsl.h \
	src/nmtui/nmt-page-ethernet.c \
	src/nmtui/nmt-page-ethernet.h \
	src/nmtui/nmt-page-infiniband.c \
	src/nmtui/nmt-page-infiniband.h \
	src/nmtui/nmt-page-ip-tunnel.c \
	src/nmtui/nmt-page-ip-tunnel.h \
	src/nmtui/nmt-page-ip4.c \
	src/nmtui/nmt-page-ip4.h \
	src/nmtui/nmt-page-ip6.c \
	src/nmtui/nmt-page-ip6.h \
	src/nmtui/nmt-page-macsec.c \
	src/nmtui/nmt-page-macsec.h \
	src/nmtui/nmt-page-ppp.c \
	src/nmtui/nmt-page-ppp.h \
	src/nmtui/nmt-page-team-port.c \
	src/nmtui/nmt-page-team-port.h \
	src/nmtui/nmt-page-team.c \
	src/nmtui/nmt-page-team.h \
	src/nmtui/nmt-page-vlan.c \
	src/nmtui/nmt-page-vlan.h \
	src/nmtui/nmt-page-wifi.c \
	src/nmtui/nmt-page-wifi.h \
	src/nmtui/nmt-page-wireguard.c \
	src/nmtui/nmt-page-wireguard.h \
	src/nmtui/nmt-password-dialog.c \
	src/nmtui/nmt-password-dialog.h \
	src/nmtui/nmt-password-fields.c \
	src/nmtui/nmt-password-fields.h \
	src/nmtui/nmt-route-editor.c \
	src/nmtui/nmt-route-editor.h \
	src/nmtui/nmt-route-entry.c \
	src/nmtui/nmt-route-entry.h \
	src/nmtui/nmt-route-table.c \
	src/nmtui/nmt-route-table.h \
	src/nmtui/nmt-slave-list.c \
	src/nmtui/nmt-slave-list.h \
	src/nmtui/nmt-utils.c \
	src/nmtui/nmt-utils.h \
	src/nmtui/nmt-widget-list.c \
	src/nmtui/nmt-widget-list.h \
	src/nmtui/nmt-wireguard-peer-editor.c \
	src/nmtui/nmt-wireguard-peer-editor.h \
	src/nmtui/nmt-wireguard-peer-list.c \
	src/nmtui/nmt-wireguard-peer-list.h \
	$(NULL)

src_nmtui_nmtui_CPPFLAGS = \
	$(clients_cppflags) \
	$(NEWT_CFLAGS) \
	$(NULL)

src_nmtui_nmtui_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS)

src_nmtui_nmtui_LDADD = \
	src/libnmt-newt/libnmt-newt.a \
	src/libnmc-setting/libnmc-setting.la \
	src/libnmc-base/libnmc-base.la \
	src/libnm-client-aux-extern/libnm-client-aux-extern.la \
	src/libnm-core-aux-extern/libnm-core-aux-extern.la \
	src/libnm-core-aux-intern/libnm-core-aux-intern.la \
	src/libnm-base/libnm-base.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	src/libnm-client-impl/libnm.la \
	$(GLIB_LIBS) \
	$(NEWT_LIBS) \
	$(NULL)

$(src_nmtui_nmtui_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_nmtui_nmtui_OBJECTS): $(src_libnm_client_public_mkenums_h)

nmtui_links = \
	nmtui-edit \
	nmtui-connect \
	nmtui-hostname \
	$(NULL)

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

EXTRA_DIST += src/nmtui/meson.build

###############################################################################
# src/nm-cloud-setup
###############################################################################

if BUILD_NM_CLOUD_SETUP

noinst_LIBRARIES += src/nm-cloud-setup/libnm-cloud-setup-core.a

src_nm_cloud_setup_libnm_cloud_setup_core_a_SOURCES = \
	src/nm-cloud-setup/nm-cloud-setup-utils.c \
	src/nm-cloud-setup/nm-cloud-setup-utils.h \
	src/nm-cloud-setup/nm-http-client.c \
	src/nm-cloud-setup/nm-http-client.h \
	src/nm-cloud-setup/nmcs-provider.c \
	src/nm-cloud-setup/nmcs-provider.h \
	src/nm-cloud-setup/nmcs-provider-ec2.c \
	src/nm-cloud-setup/nmcs-provider-ec2.h \
	src/nm-cloud-setup/nmcs-provider-gcp.c \
	src/nm-cloud-setup/nmcs-provider-gcp.h \
	src/nm-cloud-setup/nmcs-provider-azure.c \
	src/nm-cloud-setup/nmcs-provider-azure.h \
	src/nm-cloud-setup/nmcs-provider-aliyun.c \
	src/nm-cloud-setup/nmcs-provider-aliyun.h \
	$(NULL)

src_nm_cloud_setup_libnm_cloud_setup_core_a_CPPFLAGS = \
	$(clients_cppflags) \
	$(LIBCURL_CFLAGS) \
	$(NULL)

$(src_nm_cloud_setup_libnm_cloud_setup_core_a_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_nm_cloud_setup_libnm_cloud_setup_core_a_OBJECTS): $(src_libnm_client_public_mkenums_h)

libexec_PROGRAMS += src/nm-cloud-setup/nm-cloud-setup

src_nm_cloud_setup_nm_cloud_setup_SOURCES = \
	src/nm-cloud-setup/main.c \
	$(NULL)

src_nm_cloud_setup_nm_cloud_setup_CPPFLAGS = \
	$(clients_cppflags) \
	$(LIBCURL_CFLAGS) \
	$(NULL)

src_nm_cloud_setup_nm_cloud_setup_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver" \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_nm_cloud_setup_nm_cloud_setup_LDADD = \
	src/nm-cloud-setup/libnm-cloud-setup-core.a \
	src/libnm-client-aux-extern/libnm-client-aux-extern.la \
	src/libnm-core-aux-extern/libnm-core-aux-extern.la \
	src/libnm-core-aux-intern/libnm-core-aux-intern.la \
	src/libnm-base/libnm-base.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	src/libnm-client-impl/libnm.la \
	$(GLIB_LIBS) \
	$(LIBCURL_LIBS) \
	$(NULL)

$(src_nm_cloud_setup_nm_cloud_setup_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_nm_cloud_setup_nm_cloud_setup_OBJECTS): $(src_libnm_client_public_mkenums_h)

if HAVE_SYSTEMD

systemdsystemunit_DATA += \
	src/nm-cloud-setup/nm-cloud-setup.service \
	src/nm-cloud-setup/nm-cloud-setup.timer \
	$(NULL)

src/nm-cloud-setup/nm-cloud-setup.service: $(srcdir)/src/nm-cloud-setup/nm-cloud-setup.service.in
	$(AM_V_GEN) $(data_edit) $< >$@

install-data-hook-cloud-setup: install-data-hook-dispatcher
	$(INSTALL_SCRIPT) "$(srcdir)/src/nm-cloud-setup/90-nm-cloud-setup.sh" "$(DESTDIR)$(nmlibdir)/dispatcher.d/no-wait.d/"
	ln -fs no-wait.d/90-nm-cloud-setup.sh "$(DESTDIR)$(nmlibdir)/dispatcher.d/90-nm-cloud-setup.sh"

install_data_hook += install-data-hook-cloud-setup

uninstall-hook-cloud-setup:
	rm -f "$(DESTDIR)$(nmlibdir)/dispatcher.d/no-wait.d/90-nm-cloud-setup.sh"
	rm -f "$(DESTDIR)$(nmlibdir)/dispatcher.d/90-nm-cloud-setup.sh"

uninstall_hook += uninstall-hook-cloud-setup

endif

EXTRA_DIST += \
	src/nm-cloud-setup/90-nm-cloud-setup.sh \
	src/nm-cloud-setup/meson.build \
	src/nm-cloud-setup/nm-cloud-setup.service.in \
	src/nm-cloud-setup/nm-cloud-setup.timer \
	src/nm-cloud-setup/tests/meson.build \
	$(NULL)

CLEANFILES += \
	src/nm-cloud-setup/nm-cloud-setup.service

check_programs += src/nm-cloud-setup/tests/test-cloud-setup-general

src_nm_cloud_setup_tests_test_cloud_setup_general_CPPFLAGS = \
	$(clients_cppflags) \
	$(LIBCURL_CFLAGS) \
	$(NULL)

src_nm_cloud_setup_tests_test_cloud_setup_general_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS) \
	$(SANITIZER_EXEC_LDFLAGS) \
	$(NULL)

src_nm_cloud_setup_tests_test_cloud_setup_general_LDADD = \
	src/nm-cloud-setup/libnm-cloud-setup-core.a \
	src/libnm-client-aux-extern/libnm-client-aux-extern.la \
	src/libnm-core-aux-extern/libnm-core-aux-extern.la \
	src/libnm-core-aux-intern/libnm-core-aux-intern.la \
	src/libnm-base/libnm-base.la \
	src/libnm-glib-aux/libnm-glib-aux.la \
	src/libnm-log-null/libnm-log-null.la \
	src/libnm-std-aux/libnm-std-aux.la \
	src/c-siphash/libc-siphash.la \
	src/libnm-client-impl/libnm.la \
	$(GLIB_LIBS) \
	$(LIBCURL_LIBS) \
	$(NULL)

$(src_nm_cloud_setup_tests_test_cloud_setup_general_OBJECTS): $(src_libnm_core_public_mkenums_h)
$(src_nm_cloud_setup_tests_test_cloud_setup_general_OBJECTS): $(src_libnm_client_public_mkenums_h)

endif

###############################################################################
# src/tests/client
###############################################################################

check-local-tests-client: src/nmcli/nmcli src/tests/client/test-client.py
	LIBTOOL="$(LIBTOOL)" "$(srcdir)/src/tests/client/test-client.sh" "$(builddir)" "$(srcdir)" "$(PYTHON)" --

check_local += check-local-tests-client

CLEANFILES += src/tests/client/test-client.log

EXTRA_DIST += \
	src/tests/client/test-client.sh \
	src/tests/client/test-client.py \
	src/tests/client/test-client.check-on-disk/test_001.expected \
	src/tests/client/test-client.check-on-disk/test_002.expected \
	src/tests/client/test-client.check-on-disk/test_003.expected \
	src/tests/client/test-client.check-on-disk/test_004.expected \
	src/tests/client/test-client.check-on-disk/test_offline.expected \
	\
	src/tests/client/meson.build \
	$(NULL)

###############################################################################

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
	data/nm-priv-helper.service \
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

data/nm-priv-helper.service: $(srcdir)/data/nm-priv-helper.service.in
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
	data/nm-priv-helper.service.in \
	data/meson.build \
	data/nm-shared.xml \
	data/server.conf.in \
	$(NULL)

CLEANFILES += \
	data/NetworkManager-dispatcher.service \
	data/NetworkManager-wait-online.service \
	data/NetworkManager.service \
	data/nm-priv-helper.service \
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

man/nm-settings-keyfile.xml: man/nm-settings-keyfile.xsl src/libnm-client-impl/nm-property-infos-keyfile.xml man/common.ent
	$(AM_V_GEN) $(XSLTPROC) --output $@ $(xsltproc_flags) $< $(word 2,$^)
man/nm-settings-ifcfg-rh.xml: man/nm-settings-ifcfg-rh.xsl src/libnm-client-impl/nm-property-infos-ifcfg-rh.xml man/common.ent
	$(AM_V_GEN) $(XSLTPROC) --output $@ $(xsltproc_flags) $< $(word 2,$^)

CLEANFILES += $(man_nm_settings_xml)

endif

man_pages += \
	man/NetworkManager-dispatcher.8 \
	man/NetworkManager-wait-online.service.8 \
	man/NetworkManager.8 \
	man/NetworkManager.conf.5 \
	man/nm-initrd-generator.8 \
	man/nm-online.1 \
	man/nmcli-examples.7 \
	man/nmcli.1 \
	man/nmtui.1 \
	$(NULL)

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

vapi/libnm.vapi: \
	$(builddir)/src/libnm-client-impl/NM-1.0.gir \
	vapi/libnm.deps \
	vapi/NM-1.0.metadata \
	$(NULL)

vapi_libnm_vapi_METADATADIRS = $(srcdir)/vapi
vapi_libnm_vapi_FILES = $(builddir)/src/libnm-client-impl/NM-1.0.gir
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
	\
	AUTHORS \
	COPYING \
	ChangeLog \
	NEWS \
	README.md \
	\
	CONTRIBUTING.md \
	COPYING.LGPL \
	COPYING.GFDL \
	\
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
	src/meson.build \
	\
	src/libnm-core-public/nm-version-macros.h.in \
	\
	src/contrib/nm-vpn-editor-plugin-call.h \
	\
	tools/check-config-options.sh \
	tools/check-docs.sh \
	tools/check-exports.sh \
	tools/check-compare-generated.sh \
	tools/check-gitlab-ci.sh \
	tools/check-tree.sh \
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

###############################################################################

check-tree:
	"$(top_srcdir)/tools/check-tree.sh"

check_local += check-tree

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
	cscope -b -q -R -ssrc

###############################################################################

check-progs: all $(check_PROGRAMS) $(check_LTLIBRARIES)

###############################################################################

.PRECIOUS: test-suite.log
.DELETE_ON_ERROR:
.PHONY: check-progs cscope dist-configure-check $(check_local) $(dist_hook)
