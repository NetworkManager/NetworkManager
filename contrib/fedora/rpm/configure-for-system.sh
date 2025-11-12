#!/bin/bash

# Run configure/meson for NetworkManager in a way similar to how an RPM build does it.
# The effect is, that if you do `meson install`, that it will overwrite the files that
# you'd usually get by installing the NetworkManager RPM. Also, it means you can afterwards
# systemctl restart NetworkManager.

die() {
    printf "%s\n" "$*"
    exit 1
}

BASE_DIR="$(cd "$(dirname "$BASH_SOURCE")"; git rev-parse --show-toplevel)"

cd "$BASE_DIR" || die "Cannot cd to base directory"

vars() {
    sed -e '1,/[P]VARS/!d' "$BASH_SOURCE" | sed -n 's/^'"$1"'_\([^=]*\)=.*/\1/p'
}

vars_with_vals() {
    echo "Variables:"
    for v in $(vars P); do
        printf "  %s=%q\n" "$v" "$(eval "echo \"\$P_$v\"")"
    done
    echo "Directories:"
    for v in $(vars D); do
        printf "  %s=%q\n" "$v" "$(eval "echo \"\$D_$v\"")"
    done
}

usage() {
    echo "$ $0 [-m|--meson <builddir>] [-s|--show] [-B|--no-build] [-h|--help]"
    echo ""
    echo "Configure NetworkManager in a way that is similar to when building"
    echo "RPMs of NetworkManager for Fedora/RHEL. The effect is that \`meson install\`"
    echo "will overwrite the files in /usr that you installed via the package management"
    echo "systemd. Also, subsequent \`systemctl restart NetworkManager\` works."
    echo "You don't want to do this on your real system, because it messes up your"
    echo "installation"
    echo

    vars_with_vals
}

get_version() {
    grep -E -m1 '^\s+version:' meson.build | cut -d"'" -f2
}

bool() {
    case "$1" in
        1|y|Y|yes|Yes|YES|true|True|TRUE)
            return 0
            ;;
        0|n|N|no|No|NO|false|False|FALSE)
            return 1
            ;;
        *)
            local re='^[0-9]+$'
            [[ $1 =~ $re ]] && test "$1" -gt 0 && return 0
            [ "$#" -le "1" ] && return 1
            shift
            bool "$@"
            return $?
            ;;
    esac
}

bool_true() {
    if bool "$@"; then
        echo true
    else
        echo false
    fi
}

bool_not_true() {
    if bool "$@"; then
        echo false
    else
        echo true
    fi
}

bool_enable() {
    if bool "$@"; then
        echo enable
    else
        echo disable
    fi
}

bool_not_enable() {
    if bool "$@"; then
        echo disable
    else
        echo enable
    fi
}

bool_yes() {
    if bool "$@"; then
        echo yes
    else
        echo no
    fi
}

bool_not_yes() {
    if bool "$@"; then
        echo no
    else
        echo yes
    fi
}

args_enable() {
    local cond="$1"
    local a
    shift
    if bool "$cond" ; then
        for a; do
            printf "%q\n" "$a"
        done
    fi
}

show_cmd() {
    local a
    local sep=

    for a; do
        printf '%s%q' "$sep" "$a"
        sep=' '
    done
    printf '\n'
}

SHOW_CMD=

P_NOBUILD="${NOBUILD-0}"

P_DEBUG="${DEBUG-1}"

P_MESON_BUILDDIR="${MESON_BUILDDIR-./build}"
[ -n "$MESON_BUILDDIR" ] && P_MESON_BUILDDIR_FORCE=1
P_CFLAGS="${CFLAGS-}"
P_CC="${CC-$((! command -v gcc && command -v clang) &>/dev/null && echo clang || echo gcc)}"

P_RHEL="${RHEL-}"
P_FEDORA="${FEDORA-}"

P_CONFIG_PLUGINS_DEFAULT_IFCFG_RH="${CONFIG_PLUGINS_DEFAULT_IFCFG_RH-}"
P_CRYPTO="${CRYPTO-}"
P_DBUS_SYS_DIR="${DBUS_SYS_DIR-}"
P_DHCP_DEFAULT="${DHCP_DEFAULT-}"
P_DNS_RC_MANAGER_DEFAULT="${DNS_RC_MANAGER_DEFAULT-}"
P_FIREWALLD_ZONE="${FIREWALLD_ZONE-}"
P_IWD="${IWD-}"
P_LOGGING_BACKEND_DEFAULT="${LOGGING_BACKEND_DEFAULT-}"
P_LTO="${LTO-0}"
P_MODEM_MANAGER_1="${MODEM_MANAGER_1-}"
P_TEST="${TEST-1}"
P_SILENT_RULES="${SILENT_RULES-1}"

P_VERSION="${VERSION:-$(get_version)}"
P_RELEASE="${RELEASE:-$(git rev-list HEAD | wc -l).test}"

P_REGEN_DOCS="${REGEN_DOCS-1}"
P_SANITIZER="${SANITIZER-0}"

P_WIFI="${WIFI-1}"
P_WWAN="${WWAN-1}"
P_TEAM="${TEAM-1}"
P_BLUETOOTH="${BLUETOOTH-1}"
P_IFCFG_RH="${IFCFG_RH-0}"
P_NMTUI="${NMTUI-1}"
P_NM_CLOUD_SETUP="${NM_CLOUD_SETUP-1}"
P_OVS="${OVS-1}"
P_PPP="${PPP-1}"

P_PPP_VERSION="${PPP_VERSION-}"

D_PREFIX="$(rpm --eval "%{_prefix}")"
D_BINDIR="$(rpm --eval "%{_bindir}")"
D_SBINDIR="$(rpm --eval "%{_sbindir}")"
D_LIBDIR="$(rpm --eval "%{_libdir}")"
D_LIBEXECDIR="$(rpm --eval "%{_libexecdir}")"
D_INCLUDEDIR="$(rpm --eval "%{_includedir}")"
D_DATADIR="$(rpm --eval "%{_datadir}")"
D_RUNDIR="$(rpm --eval "%{_rundir}")"
D_MANDIR="$(rpm --eval "%{_mandir}")"
D_INFODIR="$(rpm --eval "%{_infodir}")"
D_SYSCONFDIR="$(rpm --eval "%{_sysconfdir}")"
D_LOCALSTATEDIR="$(rpm --eval "%{_localstatedir}")"
D_SHAREDSTATEDIR="$(rpm --eval "%{_sharedstatedir}")"

#PVARS

if [ -z "$P_FEDORA" -a -z "$P_RHEL" ] ; then
    x="$(grep -q "ID=fedora" /etc/os-release && sed -n 's/VERSION_ID=//p' /etc/os-release)"
    if test "$x" -gt 0 ; then
        P_FEDORA="$x"
        P_RHEL=0
    else
        x="$(grep -q 'ID="rhel"' /etc/os-release && sed -n 's/^VERSION_ID="*\([0-9]*\).*/\1/p' /etc/os-release)"
        if test "$x" -gt 0 ; then
            P_FEDORA=0
            P_RHEL="$x"
        fi
    fi
fi
test -z "$P_FEDORA" && P_FEDORA=0
test -z "$P_RHEL" && P_RHEL=0

test "$P_FEDORA" -gt 0 -o "$P_RHEL" -gt 0 || die "FEDORA/RHEL variables unset"

if [ -z "$P_PPP_VERSION" ] ; then
    P_PPP_VERSION="$(sed -n 's/^#define\s*VERSION\s*"\([^\s]*\)"$/\1/p' "$D_INCLUDEDIR/pppd/patchlevel.h" 2>/dev/null | grep . || echo bad)"
fi

if [ -z "$P_CRYPTO" ] ; then
    if [ "$P_FEDORA" -ge 29 -o "$P_RHEL" -ge 8  ] ; then
        P_CRYPTO=gnutls
    else
        P_CRYPTO=nss
    fi
fi

if [ -z "$P_CONFIG_PLUGINS_DEFAULT_IFCFG_RH" ] ; then
    if [ "$P_FEDORA" -ge 33 -o  "$P_RHEL" -ge 9 ] ; then
        P_CONFIG_PLUGINS_DEFAULT_IFCFG_RH=0
    else
        P_CONFIG_PLUGINS_DEFAULT_IFCFG_RH=1
    fi
fi


if [ -z "$P_DBUS_SYS_DIR" ] ; then
    if [ "$P_FEDORA" -ge 1 -o  "$P_RHEL" -ge 8 ] ; then
        P_DBUS_SYS_DIR="$D_DATADIR/dbus-1/system.d"
    else
        P_DBUS_SYS_DIR="$D_SYSCONFDIR/dbus-1/system.d"
    fi
fi

if [ -z "$P_DNS_RC_MANAGER_DEFAULT" ] ; then
    if [ "$P_FEDORA" -ge 1 -o  "$P_RHEL" -ge 9 ] ; then
        P_DNS_RC_MANAGER_DEFAULT=auto
    elif [ "$P_FEDORA" -ge 1 -o  "$P_RHEL" -ge 8 ] ; then
        P_DNS_RC_MANAGER_DEFAULT=symlink
    else
        P_DNS_RC_MANAGER_DEFAULT=file
    fi
fi

if [ -z "$P_LOGGING_BACKEND_DEFAULT" ] ; then
    if [ "$P_FEDORA" -ge 1 -o  "$P_RHEL" -ge 8 ] ; then
        P_LOGGING_BACKEND_DEFAULT=journal
    else
        P_LOGGING_BACKEND_DEFAULT=syslog
    fi
fi

if [ -z "$P_DHCP_DEFAULT" ] ; then
    if [ "$P_FEDORA" -ge 31 -o "$P_RHEL" -ge 8 ] ; then
        P_DHCP_DEFAULT=internal
    else
        P_DHCP_DEFAULT=dhclient
    fi
fi

if [ -z "$P_FIREWALLD_ZONE" ] ; then
    if [ "$P_FEDORA" -ge 32 -o "$P_RHEL" -ge 8 ] ; then
        P_FIREWALLD_ZONE=1
    else
        P_FIREWALLD_ZONE=0
    fi
fi

if [ -z "$P_IWD" ] ; then
    if [ "$P_RHEL" -ge 1 ] ; then
        P_IWD=0
    else
        P_IWD=1
    fi
fi

if [ -z "$P_MODEM_MANAGER_1" ] ; then
    if bool "$P_BLUETOOTH" || bool "$P_WWAN" ; then
        P_MODEM_MANAGER_1=1
    else
        P_MODEM_MANAGER_1=0
    fi
fi

if [ -z "$TEAM" ] && [ "${P_RHEL-0}" -ge 10 ] ; then
    P_TEAM=0
fi

if [ -z "$IFCFG_RH" ] && [ -n "$P_RHEL" ] && [ "$P_RHEL" -le 9 ] ; then
    P_IFCFG_RH=1
fi

if bool "$P_DEBUG" ; then
    P_CFLAGS="-g -Og -fexceptions${P_CFLAGS:+ }$P_CFLAGS"
else
    P_CFLAGS="-g -O2 -fexceptions${P_CFLAGS:+ }$P_CFLAGS"
fi

while [[ $# -gt 0 ]] ; do
    A="$1"
    shift
    case "$A" in
        --meson|-m)
            P_MESON_BUILDDIR="$1"
            P_MESON_BUILDDIR_FORCE=1
            shift
            ;;
        -s|--show)
            SHOW_CMD=show_cmd
            ;;
        -h|help|-help|--help)
            usage
            exit 0
            ;;
        -B|--no-build)
            P_NOBUILD=1
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

if [ "$P_MESON_BUILDDIR_FORCE" != 1 ]; then
    if [ -d "$P_MESON_BUILDDIR" ]; then
        echo "Build directory '$P_MESON_BUILDDIR' chosen by default, but it exists and will be overwritten." \
             "If you really want that, pass '--meson \"$P_MESON_BUILDDIR\"'." >&2
        exit 1
    fi
fi

vars_with_vals

MESON_RECONFIGURE=
if test -d "$P_MESON_BUILDDIR" ; then
    MESON_RECONFIGURE="--reconfigure"
fi

$SHOW_CMD \
env \
CC="$P_CC" \
CFLAGS="$P_CFLAGS" \
meson setup\
    $MESON_RECONFIGURE \
    --buildtype=plain \
    --prefix="$D_PREFIX" \
    --libdir="$D_LIBDIR" \
    --libexecdir="$D_LIBEXECDIR" \
    --bindir="$D_BINDIR" \
    --sbindir="$D_SBINDIR" \
    --includedir="$D_INCLUDEDIR" \
    --datadir="$D_DATADIR" \
    --mandir="$D_MANDIR" \
    --infodir="$D_INFODIR" \
    --localedir="$D_DATADIR"/locale \
    --sysconfdir="$D_SYSCONFDIR" \
    --localstatedir="$D_LOCALSTATEDIR" \
    --sharedstatedir="$D_SHAREDSTATEDIR" \
    --wrap-mode=nodownload \
    --auto-features=enabled \
    -Db_ndebug=false \
    --warnlevel 2 \
    $(args_enable "$P_TEST" --werror) \
    -Dnft="${D_SBINDIR}/nft" \
    -Diptables="${D_SBINDIR}/iptables" \
    -Dip6tables="${D_SBINDIR}/ip6tables" \
    -Ddhclient="${D_SBINDIR}/dhclient" \
    -Ddhcpcd=no \
    -Dconfig_dhcp_default="$P_DHCP_DEFAULT" \
    "-Dcrypto=$P_CRYPTO" \
    $(args_enable "$P_DEBUG"                    -Dmore_logging=true  -Dmore_asserts=10000) \
    $(args_enable "$(bool_not_true "$P_DEBUG")" -Dmore_logging=false -Dmore_asserts=0    ) \
    -Dld_gc=true \
    -Db_lto="$(bool_true "$P_LTO")" \
    -Dlibaudit=yes-disabled-by-default \
    -Dmodem_manager="$(bool_true "$P_MODEM_MANAGER_1")" \
    $(args_enable "$P_WIFI"                    -Dwifi=true  -Dwext=false) \
    $(args_enable "$(bool_not_true "$P_WIFI")" -Dwifi=false                                  ) \
    -Diwd="$(bool_true "$P_IWD")" \
    -Dbluez5_dun="$(bool_true "$P_BLUETOOTH")" \
    -Dnmtui="$(bool_true "$P_NMTUI")" \
    -Dnm_cloud_setup="$(bool_true "$P_NM_CLOUD_SETUP")" \
    -Dvapi=true \
    -Dintrospection=true \
    -Ddocs="$(bool_true "$P_REGEN_DOCS")" \
    -Dteamdctl="$(bool_true "$P_TEAM")" \
    -Dovs="$(bool_true "$P_OVS")" \
    -Dselinux=true \
    -Dpolkit=true  \
    -Dconfig_auth_polkit_default=true \
    -Dconcheck=true \
    -Dlibpsl="$(bool_true "$P_FEDORA")" \
    -Dsession_tracking=systemd \
    -Dsuspend_resume=systemd \
    -Dsystemdsystemunitdir=/usr/lib/systemd/system \
    -Dsystemdsystemgeneratordir=/usr/lib/systemd/system-generators \
    -Dsystem_ca_path=/etc/pki/tls/cert.pem \
    -Ddbus_conf_dir="$P_DBUS_SYS_DIR" \
    -Dtests=yes \
    -Dvalgrind=no \
    -Difcfg_rh="$(bool_true "$P_IFCFG_RH")" \
    -Difupdown=false \
    $(args_enable "$P_PPP"                    -Dppp=true  -Dpppd="$D_SBINDIR/pppd" -Dpppd_plugin_dir="$D_LIBDIR/pppd/$P_PPP_VERSION") \
    $(args_enable "$(bool_not_true "$P_PPP")" -Dppp=false                                                                           ) \
    -Dfirewalld_zone="$(bool_true "$P_FIREWALLD_ZONE}")" \
    -Ddist_version="$P_VERSION-$P_RELEASE" \
    $(args_enable "$P_CONFIG_PLUGINS_DEFAULT_IFCFG_RH" -Dconfig_plugins_default=ifcfg-rh) \
    -Dresolvconf=no \
    -Dnetconfig=no \
    -Dconfig_dns_rc_manager_default="$P_DNS_RC_MANAGER_DEFAULT" \
    -Dconfig_logging_backend_default="$P_LOGGING_BACKEND_DEFAULT" \
    \
    "$P_MESON_BUILDDIR" \
    ;

if ! bool "$P_NOBUILD" ; then
    $SHOW_CMD ninja -C "$P_MESON_BUILDDIR"
fi
