#!/bin/bash

set -e

###############################################################################
# Script to create a podman container for testing NetworkManager.
#
# Commands:
#  - build: build a new image, named "$CONTAINER_NAME_REPOSITORY:$CONTAINER_NAME_TAG" ("nm:nm")
#  - run: start the container and tag it "$CONTAINER_NAME_NAME" ("nm")
#  - exec: run bash inside the container
#  - stop: stop the container
#  - clean: delete the container and the image.
#
# Options:
#  --no-cleanup: don't delete the CONTAINERFILE and other artifacts
#  --stop: only has effect with "run". It will stop the container afterwards.
#  -- [COMMAND]: with command "exec", provide a command to run in the container.
#    Defaults to "bash".
#
# It bind mounts the current working directory inside the container.
# You can run `make install` and run tests.
# There is a script nm-env-prepare.sh to generate a net1 interface for testing.
###############################################################################

BASE_IMAGE="${BASE_IMAGE:-fedora:latest}"

BASEDIR_NM="$(readlink -f "$(dirname "$(readlink -f "$0")")/../..")"
BASEDIR="$BASEDIR_NM/contrib/scripts/nm-in-container.d"

CONTAINER_NAME_REPOSITORY=${CONTAINER_NAME_REPOSITORY:-nm}
CONTAINER_NAME_TAG=${CONTAINER_NAME_TAG:-nm}
CONTAINER_NAME_NAME=${CONTAINER_NAME_NAME:-nm}

###############################################################################

usage() {
    cat <<EOF
$0: build|run|exec|stop|clean [--no-cleanup] [--stop]
EOF
    echo
    awk '/^####*$/{ if(on) exit; on=1} { if (on) { if (on==2) print(substr($0,3)); on=2; } }' "$BASH_SOURCE"
    echo
}

###############################################################################

die() {
    (
        echo -n -e "\033[31m"
        printf "%s" "$*"
        echo -e "\033[0m"
    ) >&2
    exit 1
}

###############################################################################

CLEANUP_FILES=()
DO_CLEANUP=1
cleanup() {
    test "$DO_CLEANUP" = 1 || return 0
    for f in "${CLEANUP_FILES[@]}" ; do
        rm -rf "$f"
    done
}

trap cleanup EXIT

###############################################################################

tmp_file() {
    cat > "$1"
    CLEANUP_FILES+=( "$1" )
    test -z "$2" || chmod "$2" "$1"
}

bind_files() {
    VARIABLE_NAME="$1"

    ARR=()
    H=~

    for f in ~/.gitconfig* ~/.vim* ; do
        test -e "$f" || continue
        f2="${f#$H/}"
        [[ "$f2" = .viminf* ]] && continue
        [[ "$f2" = *.tmp ]] && continue
        [[ "$f2" = *~ ]] && continue
        f2="/root/$f2"
        ARR+=( -v "$f:$f2:Z" )
    done

    eval "$VARIABLE_NAME=( \"\${ARR[@]}\" )"
}

create_dockerfile() {

    local CONTAINERFILE="$1"
    local BASE_IMAGE="$2"

    cp "$BASEDIR_NM/contrib/scripts/NM-log" "$BASEDIR/data-NM-log"
    CLEANUP_FILES+=( "$BASEDIR/data-NM-log" )

    cat <<EOF | tmp_file "$BASEDIR/data-motd"
*** nm-in-container:

find NetworkManager bind mounted at $BASEDIR_NM
run \`nm-env-prepare.sh setup --idx 1\` to setup test interfaces

Configure NetworkManager with
  \$ ./configure \\
           --enable-address-sanitizer=no \\
           --enable-compile-warnings=yes \\
           --enable-concheck \\
           --enable-config-plugin-ibft=yes \\
           --enable-gtk-doc \\
           --enable-ifcfg-rh=yes \\
           --enable-ifcfg-suse \\
           --enable-ifnet \\
           --enable-ifupdown=yes \\
           --enable-introspection \\
           --enable-json-validation=yes \\
           --enable-maintainer-mode \\
           --enable-more-logging \\
           --enable-more-warnings=error \\
           --enable-ovs=yes \\
           --enable-polkit=yes \\
           --enable-teamdctl=yes \\
           --enable-undefined-sanitizer=no \\
           --enable-vala=yes \\
           --enable-wimax \\
           --localstatedir=/var \\
           --prefix=/opt/test \\
           --sysconfdir=/etc \\
           --with-config-dhcp-default=internal \\
           --with-config-dns-rc-manager-default=auto \\
           --with-consolekit=yes \\
           --with-consolekit=yes \\
           --with-crypto=nss \\
           --with-dhclient=yes \\
           --with-dhcpcanon=yes \\
           --with-dhcpcd=yes \\
           --with-iwd=yes \\
           --with-libnm-glib=yes \\
           --with-modem-manager-1 \\
           --with-netconfig=/bin/nowhere/netconfig \\
           --with-nm-cloud-setup=yes \\
           --with-nmcli=yes \\
           --with-nmtui=yes \\
           --with-ofono=yes \\
           --with-resolvconf=/bin/nowhere/resolvconf \\
           --with-session-tracking=systemd \\
           --with-suspend-resume=systemd \\
           --with-systemd-logind=yes \\
           --with-valgrind=yes \\
           --enable-tests="\${NM_BUILD_TESTS:-yes}" \\
           --with-more-asserts="\${NM_BUILD_MORE_ASSERTS:-1000}" \\
           "\${NM_CONFIGURE_OTPS[@]}"
Test with:
  \$ systemctl stop NetworkManager; /opt/test/sbin/NetworkManager --debug 2>&1 | tee -a /tmp/nm-log.txt
EOF

    cat <<EOF | tmp_file "$BASEDIR/data-bashrc.my"
alias m="make -j 8"
alias n="ninja -C build"

alias l='ls -l --color=auto'

Clean() {
    systemctl stop NetworkManager
    rm -i -rf /run/NetworkManager
    nm-env-prepare.sh
}

Cat-Timestamp() {
    while IFS=$'\n' read line; do
        printf "[%s]: %s\n" "$(date '+%s.%N')" "$line"
    done
}

nm_run_gdb() {
    systemctl stop NetworkManager.service
    gdb --args "\${1:-/opt/test/sbin/NetworkManager}" --debug
}

nm_run_normal() {
    systemctl stop NetworkManager.service
    "\${1:-/opt/test/sbin/NetworkManager}" --debug 2>&1 | tee /tmp/nm-log.txt
}

. /usr/share/git-core/contrib/completion/git-prompt.sh
PS1="\[\\033[01;36m\]\u@\h\[\\033[00m\]:\\t:\[\\033[01;34m\]\w\\\$(__git_ps1 \\" \[\\033[01;36m\](%s)\[\\033[00m\]\\")\[\\033[00m\]\$ "
export GIT_PS1_SHOWDIRTYSTATE=1

if test "\$SHOW_MOTD" != 0; then
  cat /etc/motd
  export SHOW_MOTD=0
fi
EOF

    cat <<EOF | tmp_file "$BASEDIR/data-90-my.conf"
[main]
no-auto-default=*
debug=RLIMIT_CORE,fatal-warnings

[logging]
level=TRACE
domains=ALL,VPN_PLUGIN:TRACE

[device-managed-0]
match-device=interface-name:d_*,interface-name:tap*
managed=0

[device-managed-1]
match-device=interface-name:net*,interface-name:eth*
managed=1
EOF

    cat <<EOF | tmp_file "$BASEDIR/data-bash_history" 600
NM-log
NM-log /tmp/nm-log.txt
behave -f html --stop ./features/scenarios/vrf.feature
behave -f html --stop -t ipv4_method_static_with_IP ./features/scenarios/ipv4.feature
cd $BASEDIR_NM
journalctl | NM-log
nm-env-prepare.sh
nm-env-prepare.sh --prefix eth -i 4
nm_run_gdb
nm_run_normal
nmcli device connect net1
nmcli connection add type pppoe con-name ppp-net1 ifname ppp-net1 pppoe.parent net1 service isp username test password networkmanager autoconnect no
for i in {1..9}; do nm-env-prepare.sh --prefix eth -i \$i; done
systemctl status NetworkManager
systemctl stop NetworkManager
systemctl stop NetworkManager; /opt/test/sbin/NetworkManager --debug 2>&1 | tee -a /tmp/nm-log.txt
systemctl stop NetworkManager; gdb -ex run --args /opt/test/sbin/NetworkManager --debug
EOF

    cat <<EOF | tmp_file "$BASEDIR/data-gdbinit"
set history save
set history filename ~/.gdb_history
EOF

    cat <<EOF | tmp_file "$BASEDIR/data-gdb_history" 600
run
run --debug 2>&1 | tee /tmp/nm-log.txt
EOF

    cat <<EOF | tmp_file "$BASEDIR/data-behaverc" 600
[behave.formatters]
html = behave_html_formatter:HTMLFormatter
EOF

    cat <<EOF | tmp_file "$CONTAINERFILE"
FROM $BASE_IMAGE

ENTRYPOINT ["/sbin/init"]

RUN dnf install -y \\
    ModemManager-devel \\
    ModemManager-glib-devel \\
    NetworkManager \\
    audit-libs-devel \\
    bash-completion \\
    bind-utils \\
    bluez-libs-devel \\
    cscope \\
    dbus-devel \\
    dbus-x11 \\
    dhclient \\
    dnsmasq \\
    firewalld-filesystem \\
    gcc-c++ \\
    gdb \\
    gettext-devel \\
    git \\
    glib2-doc \\
    gnutls-devel \\
    gobject-introspection-devel \\
    gtk-doc \\
    intltool \\
    iproute \\
    iptables \\
    jansson-devel \\
    libasan \\
    libcurl-devel \\
    libndp-devel \\
    libpsl-devel \\
    libselinux-devel \\
    libtool \\
    libuuid-devel \\
    make \\
    meson \\
    meson \\
    mlocate \\
    mobile-broadband-provider-info-devel \\
    newt-devel \\
    nispor \\
    nmstate \\
    nss-devel \\
    polkit-devel \\
    ppp \\
    ppp-devel \\
    procps \\
    python3-behave \\
    python3-dbus \\
    python3-devel \\
    python3-gobject \\
    python3-pexpect \\
    python3-pip \\
    python3-pyte \\
    python3-pyyaml \\
    radvd \\
    readline-devel \\
    rp-pppoe \\
    rpm-build \\
    strace \\
    systemd \\
    systemd-devel \\
    teamd-devel \\
    vala \\
    vala-devel \\
    valgrind \\
    vim \\
    which

RUN dnf debuginfo-install --skip-broken \$(ldd /usr/sbin/NetworkManager | sed -n 's/.* => \\(.*\\) (0x[0-9A-Fa-f]*)$/\1/p' | xargs -n1 readlink -f) -y

RUN pip3 install --user behave_html_formatter || true

RUN systemctl enable NetworkManager

COPY data-NM-log "/usr/bin/NM-log"
COPY data-nm-env-prepare.sh "/usr/bin/nm-env-prepare.sh"
COPY data-motd /etc/motd
COPY data-bashrc.my /etc/bashrc.my
COPY data-90-my.conf /etc/NetworkManager/conf.d/90-my.conf
COPY data-bash_history /root/.bash_history
COPY data-gdbinit /root/.gdbinit
COPY data-gdb_history /root/.gdb_history
COPY data-behaverc /root/.behaverc

# Generate a stable machine id.
RUN echo "10001000100010001000100010001000" > /etc/machine-id

# Generate a fixed (version 1) secret key.
RUN mkdir -p /var/lib/NetworkManager
RUN chmod 700 /var/lib/NetworkManager
RUN echo -n "nm-in-container-secret-key" > /var/lib/NetworkManager/secret_key
RUN chmod 600 /var/lib/NetworkManager/secret_key

RUN sed 's/.*RateLimitBurst=.*/RateLimitBurst=0/' /etc/systemd/journald.conf -i

RUN rm -rf /etc/NetworkManager/system-connections/*

RUN echo -e '\n. /etc/bashrc.my\n' >> /etc/bashrc

RUN updatedb
EOF
}

###############################################################################

container_image_exists() {
    podman image exists "$1" || return 1
}

container_exists() {
    podman container exists "$1" || return 1
}

container_is_running() {
    test "$(podman ps --format "{{.ID}} {{.Names}}" | sed -n "s/ $1\$/\0/p")" != "" || return 1
}

###############################################################################

do_clean() {
    podman stop "$CONTAINER_NAME_NAME" || :
    podman rm "$CONTAINER_NAME_NAME" || :
    podman rmi "$CONTAINER_NAME_REPOSITORY:$CONTAINER_NAME_TAG" || :
}

do_build() {
    container_image_exists "$CONTAINER_NAME_REPOSITORY:$CONTAINER_NAME_TAG" && return 0

    CONTAINERFILE="$BASEDIR/containerfile"
    create_dockerfile "$CONTAINERFILE" "$BASE_IMAGE"
    podman build --tag "$CONTAINER_NAME_REPOSITORY:$CONTAINER_NAME_TAG" -f "$CONTAINERFILE"
}

do_run() {
    do_build

    if container_is_running "$CONTAINER_NAME_NAME" ; then
        return 0
    fi

    if container_exists "$CONTAINER_NAME_NAME" ; then
        podman start "$CONTAINER_NAME_NAME"
    else
        bind_files BIND_FILES

        BIND_NM_CI=()
        if [ -d "$BASEDIR_NM/.git/NetworkManager-ci" ] ; then
            DIR="$(readlink -f "$BASEDIR_NM/.git/NetworkManager-ci")"
            BIND_NM_CI=(-v "$DIR:$DIR:Z")
        fi

        podman run --privileged \
            --name "$CONTAINER_NAME_NAME" \
            -d \
            -v "$BASEDIR_NM:$BASEDIR_NM" \
            "${BIND_NM_CI[@]}" \
            "${BIND_FILES[@]}" \
            "$CONTAINER_NAME_REPOSITORY:$CONTAINER_NAME_TAG"
    fi
}

do_exec() {
    do_run

    local EXTRA_ARGS=("$@")
    if [ "${#EXTRA_ARGS[@]}" = 0 ]; then
        EXTRA_ARGS=('bash')
    fi

    podman exec --workdir "$BASEDIR_NM" -it "$CONTAINER_NAME_NAME" "${EXTRA_ARGS[@]}"

    if [ "$DO_STOP" = 1 ]; then
        do_stop
    fi
}

do_stop() {
    container_is_running "$CONTAINER_NAME_NAME" || return 0
    podman stop "$CONTAINER_NAME_NAME"
}

###############################################################################

DO_STOP=0
CMD=exec
EXTRA_ARGS=()
for (( i=1 ; i<="$#" ; )) ; do
    c="${@:$i:1}"
    i=$((i+1))
    case "$c" in
        --no-cleanup)
            DO_CLEANUP=0
            ;;
        --stop)
            DO_STOP=1
            ;;
        build|run|exec|stop|clean)
            CMD=$c
            ;;
        --)
            EXTRA_ARGS=( "${@:$i}" )
            break
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            die "invalid argument: $c"
            ;;
    esac
done

###############################################################################

test "$UID" != 0 || die "cannot run as root"

if test $CMD != exec && test "${#EXTRA_ARGS[@]}" != 0 ; then
    die "Extra arguments are only allowed with exec command"
fi

###############################################################################

do_$CMD "${EXTRA_ARGS[@]}"
