#!/bin/bash

# Run configure/meson for NetworkManager in a way similar to how an RPM build does it.
# The effect is, that if you do `make install`, that it will overwrite the files that
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
    echo "$ $0 [-m|--meson] [-a|--autotools] [-s|--show] [-B|--no-build] [-h|--help]"
    echo ""
    echo "Configure NetworkManager in a way that is similar to when building"
    echo "RPMs of NetworkManager for Fedora/RHEL. The effect is that \`make install\`"
    echo "will overwrite the files in /usr that you installed via the package management"
    echo "systemd. Also, subsequent \`systemctl restart NetworkManager\` works."
    echo "You don't want to do this on your real system, because it messes up your"
    echo "installation"
    echo

    vars_with_vals
}

get_version() {
    local major minor micro
    local F="./configure.ac"

    vars="$(sed -n 's/^m4_define(\[nm_\(major\|minor\|micro\)_version\], *\[\([0-9]\+\)\]) *$/local \1='\''\2'\''/p' "$F" 2>/dev/null)"
    eval "$vars"

    [[ -n "$major" && -n "$minor" && "$micro" ]] || return 1
    echo "$major.$minor.$micro"
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

P_BUILD_TYPE="${BUILD_TYPE-}"
P_CFLAGS="${CFLAGS-}"
P_CC="${CC-$((! command -v gcc && command -v clang) &>/dev/null && echo clang || echo gcc)}"

P_RHEL="${RHEL-}"
P_FEDORA="${FEDORA-}"

P_CONFIG_PLUGINS_DEFAULT_IFCFG_RH="${CONFIG_PLUGINS_DEFAULT_IFCFG_RH-}"
P_CRYPTO="${CRYPTO-}"
P_DBUS_SYS_DIR="${DBUS_SYS_DIR-}"
P_DHCP_DEFAULT="${DHCP_DEFAULT-}"
P_DNS_RC_MANAGER_DEFAULT="${DNS_RC_MANAGER_DEFAULT-}"
P_EBPF_ENABLED="${EBPF_ENABLED-no}"
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
        x="$(grep -q "ID=fedora" /etc/os-release && sed -n 's/VERSION_ID=//p' /etc/os-release)"
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

if bool "$P_DEBUG" ; then
    P_CFLAGS="-g -Og -fexceptions${P_CFLAGS:+ }$P_CFLAGS"
else
    P_CFLAGS="-g -O2 -fexceptions${P_CFLAGS:+ }$P_CFLAGS"
fi

if [ -z "$P_BUILD_TYPE" ] ; then
    if [ -d ./build -a ! -f ./configure ] ; then
        P_BUILD_TYPE=meson
    elif [ ! -d ./build -a -f ./configure ] ; then
        P_BUILD_TYPE=autotools
    else
        P_BUILD_TYPE=autotools
    fi
fi

while [[ $# -gt 0 ]] ; do
    A="$1"
    shift
    case "$A" in
        --meson|-m)
            P_BUILD_TYPE=meson
            ;;
        --autotools|-a)
            P_BUILD_TYPE=autotools
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

vars_with_vals

if [ "$P_BUILD_TYPE" == meson ] ; then
    MESON_RECONFIGURE=
    if test -d "./build/" ; then
        MESON_RECONFIGURE="--reconfigure"
    fi

    $SHOW_CMD \
    env \
    CC="$P_CC" \
    CFLAGS="$P_CFLAGS" \
    meson \
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
        \
        build \
        \
        $MESON_RECONFIGURE \
        \
        -Db_ndebug=false \
        --warnlevel 2 \
        $(args_enable "$P_TEST" --werror) \
        -Dnft="${D_SBINDIR}/nft" \
        -Diptables="${D_SBINDIR}/iptables" \
        -Ddhclient="${D_SBINDIR}/dhclient" \
        -Ddhcpcanon=no \
        -Ddhcpcd=no \
        -Dconfig_dhcp_default="$P_DHCP_DEFAULT" \
        "-Dcrypto=$P_CRYPTO" \
        $(args_enable "$P_DEBUG"                    -Dmore_logging=true  -Dmore_asserts=10000) \
        $(args_enable "$(bool_not_true "$P_DEBUG")" -Dmore_logging=false -Dmore_asserts=0    ) \
        -Dld_gc=true \
        -Db_lto="$(bool_true "$P_LTO")" \
        -Dlibaudit=yes-disabled-by-default \
        -Dmodem_manager="$(bool_true "$P_MODEM_MANAGER_1")" \
        $(args_enable "$P_WIFI"                    -Dwifi=true  -Dwext="$(bool_true "$P_FEDORA")") \
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
        -Dmodify_system=true \
        -Dconcheck=true \
        -Dlibpsl="$(bool_true "$P_FEDORA")" \
        -Debpf="$(bool_true "$P_EBPF_ENABLED")" \
        -Dsession_tracking=systemd \
        -Dsuspend_resume=systemd \
        -Dsystemdsystemunitdir=/usr/lib/systemd/system \
        -Dsystem_ca_path=/etc/pki/tls/cert.pem \
        -Ddbus_conf_dir="$P_DBUS_SYS_DIR" \
        -Dtests=yes \
        -Dvalgrind=no \
        -Difcfg_rh=true \
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
        ;
else
    if ! test -x ./configure ; then
        if [ -z "$SHOW_CMD" ]; then
            NOCONFIGURE=yes ./autogen.sh
        fi
    fi
    $SHOW_CMD \
    ./configure \
        --build=x86_64-redhat-linux-gnu \
        --host=x86_64-redhat-linux-gnu \
        --program-prefix= \
        --prefix="$D_PREFIX" \
        --exec-prefix=/usr \
        --bindir="$D_BINDIR" \
        --sbindir="$D_SBINDIR" \
        --sysconfdir="$D_SYSCONFDIR" \
        --datadir="$D_DATADIR" \
        --includedir="$D_INCLUDEDIR" \
        --libdir="$D_LIBDIR" \
        --libexecdir="$D_LIBEXECDIR" \
        --localstatedir="$D_LOCALSTATEDIR" \
        --sharedstatedir="$D_SHAREDSTATEDIR" \
        --mandir="$D_MANDIR" \
        --infodir="$D_INFODIR" \
        \
        CC="$P_CC" \
        CFLAGS="$P_CFLAGS" \
        \
        --enable-dependency-tracking=yes \
        \
        --with-runstatedir="$D_RUNDIR" \
        --enable-silent-rules="$(bool_yes "$P_SILENT_RULES")" \
        --enable-static=no \
        --with-nft="${D_SBINDIR}/nft" \
        --with-iptables="${D_SBINDIR}/iptables" \
        --with-dhclient="${D_SBINDIR}/dhclient" \
        --with-dhcpcd=no \
        --with-dhcpcanon=no \
        --with-config-dhcp-default="$P_DHCP_DEFAULT" \
        --with-crypto="$P_CRYPTO" \
        $(args_enable "$P_SANITIZER"                    --with-address-sanitizer=exec --enable-undefined-sanitizer="$( (bool "$P_FEDORA" || test "$P_RHEL" -ge 8) && echo yes || echo no)" ) \
        $(args_enable "$(bool_not_true "$P_SANITIZER")" --with-address-sanitizer=no   --enable-undefined-sanitizer=no                                                                            ) \
        $(args_enable "$P_DEBUG"                    --enable-more-logging=yes --with-more-asserts=10000) \
        $(args_enable "$(bool_not_true "$P_DEBUG")" --enable-more-logging=no  --with-more-asserts=0    ) \
        --enable-ld-gc=yes \
        --enable-lto="$(bool_yes "$P_LTO")" \
        --with-libaudit=yes-disabled-by-default \
        --with-modem-manager-1="$(bool_yes "$P_MODEM_MANAGER_1")" \
        $(args_enable "$P_WIFI"                    --enable-wifi=yes --with-wext="$(bool_yes "$P_FEDORA")") \
        $(args_enable "$(bool_not_true "$P_WIFI")" --enable-wifi=no                                       ) \
        --with-iwd="$(bool_yes "$P_IWD")" \
        --enable-bluez5-dun="$(bool_yes "$P_BLUETOOTH")" \
        --with-nmtui="$(bool_yes "$P_NMTUI")" \
        --with-nm-cloud-setup="$(bool_yes "$P_NM_CLOUD_SETUP")" \
        --enable-vala=yes \
        --enable-introspection=yes \
        --enable-gtk-doc="$(bool_yes "$P_REGEN_DOCS")" \
        --enable-teamdctl="$(bool_yes "$P_TEAM")" \
        --enable-ovs="$(bool_yes "$P_OVS")" \
        --with-selinux=yes \
        --enable-polkit=yes \
        --enable-modify-system=yes \
        --enable-concheck=yes \
        --with-libpsl="$(bool_yes "$P_FEDORA")" \
        --with-ebpf="$(bool_yes "$P_EBPF_ENABLED")" \
        --with-session-tracking=systemd \
        --with-suspend-resume=systemd \
        --with-systemdsystemunitdir=/usr/lib/systemd/system \
        --with-system-ca-path=/etc/pki/tls/cert.pem \
        --with-dbus-sys-dir="$P_DBUS_SYS_DIR" \
        --with-tests=yes \
        --enable-more-warnings="$(bool "$P_TEST" && echo error || echo yes)" \
        --with-valgrind=no \
        --enable-ifcfg-rh=yes \
        --enable-ifupdown=no \
        $(args_enable "$P_PPP"                    --enable-ppp=yes --with-pppd="$D_SBINDIR/pppd" --with-pppd-plugin-dir="$D_LIBDIR/pppd/$P_PPP_VERSION") \
        $(args_enable "$(bool_not_true "$P_PPP")" --enable-ppp=no                                                                                      ) \
        --enable-firewalld-zone="$(bool_yes "$P_FIREWALLD_ZONE")" \
        --with-dist-version="$P_VERSION-$P_RELEASE" \
        $(args_enable "$P_CONFIG_PLUGINS_DEFAULT_IFCFG_RH" --with-config-plugins-default=ifcfg-rh) \
        --with-resolvconf=no \
        --with-netconfig=no \
        --with-config-dns-rc-manager-default="$P_DNS_RC_MANAGER_DEFAULT" \
        --with-config-logging-backend-default="$P_LOGGING_BACKEND_DEFAULT" \
        ;
fi

if ! bool "$P_NOBUILD" ; then
    if [ "$P_BUILD_TYPE" == meson ] ; then
        $SHOW_CMD ninja -C build
    else
        $SHOW_CMD make -j 10
    fi
fi
