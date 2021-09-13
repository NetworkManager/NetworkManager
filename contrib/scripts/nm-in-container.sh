#!/bin/bash

set -e

###############################################################################

BASE_IMAGE="${BASE_IMAGE:-fedora:latest}"

BASEDIR_NM="$(readlink -f "$(dirname "$(readlink -f "$0")")/../..")"
BASEDIR="$BASEDIR_NM/contrib/scripts/nm-in-container.d"

CONTAINER_NAME_REPOSITORY=${CONTAINER_NAME_REPOSITORY:-my}
CONTAINER_NAME_TAG=${CONTAINER_NAME_TAG:-nm}
CONTAINER_NAME_NAME=${CONTAINER_NAME_NAME:-nm}

###############################################################################

die() {
    printf "%s\n" "$*" >&2
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

bind_files() {
    VARIABLE_NAME="$1"

    ARR=()
    H=~

    for f in ~/.gitconfig* ~/.vim* ; do
        test -f "$f" || continue
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

    DOCKERFILE="$1"
    BASE_IMAGE="$2"

    cp "$BASEDIR_NM/contrib/scripts/NM-log" "$BASEDIR/data-NM-log"
    CLEANUP_FILES+=( "$BASEDIR/data-NM-log" )

    cat <<EOF >  "$BASEDIR/data-motd"
*** nm-in-container:

find NetworkManager bind mounted at $BASEDIR_NM
run \`nm-env-prepare.sh setup --idx 1\` to setup test interfaces

Configure NetworkManager with
  \$ ./configure --enable-maintainer-mode --enable-more-warnings=error --with-more-asserts="\${NM_BUILD_MORE_ASSERTS:-1000}" --with-nm-cloud-setup=yes --prefix=/opt/test --localstatedir=/var --sysconfdir=/etc --enable-gtk-doc --enable-introspection --with-ofono=yes --with-dhclient=yes --with-dhcpcanon=yes --with-dhcpcd=yes --enable-more-logging --enable-compile-warnings=yes --enable-address-sanitizer=no --enable-undefined-sanitizer=no --with-valgrind=yes --enable-concheck --enable-wimax --enable-ifcfg-rh=yes --enable-config-plugin-ibft=yes --enable-ifcfg-suse --enable-ifupdown=yes --enable-ifnet --enable-vala=yes --enable-polkit=yes --with-libnm-glib=yes --with-nmcli=yes --with-nmtui=yes --with-modem-manager-1 --with-suspend-resume=systemd --enable-teamdctl=yes --enable-ovs=yes --enable-tests=${NM_BUILD_TESTS} --with-netconfig=/bin/nowhere/netconfig --with-resolvconf=/bin/nowhere/resolvconf --with-crypto=nss --with-session-tracking=systemd --with-consolekit=yes --with-systemd-logind=yes --with-iwd=yes --enable-json-validation=yes --with-consolekit=yes --with-config-dns-rc-manager-default=auto --with-config-dhcp-default=internal "\${NM_CONFIGURE_OTPS[@]}"
Test with:
  \$ systemctl stop NetworkManager; /opt/test/sbin/NetworkManager --debug 2>&1 | tee -a /tmp/nm-log.txt
EOF
    CLEANUP_FILES+=( "$BASEDIR/data-motd" )

    cat <<EOF > "$DOCKERFILE"
FROM $BASE_IMAGE

ENTRYPOINT ["/sbin/init"]

RUN dnf install -y \\
    ModemManager-devel \\
    ModemManager-glib-devel \\
    NetworkManager \\
    audit-libs-devel \\
    bash-completion \\
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
    mobile-broadband-provider-info-devel \\
    newt-devel \\
    nss-devel \\
    polkit-devel \\
    ppp \\
    ppp-devel \\
    procps \\
    python3-dbus \\
    python3-devel \\
    python3-gobject \\
    python3-pip \\
    python3-pip \\
    radvd \\
    readline-devel \\
    rpm-build \\
    strace \\
    systemd \\
    systemd-devel \\
    teamd-devel \\
    vala-devel \\
    vala-tools \\
    valgrind \\
    vim \\
    which

RUN pip install gdbgui
RUN systemctl enable NetworkManager
RUN dnf clean all

COPY data-NM-log "/usr/bin/NM-log"
COPY data-nm-env-prepare.sh "/usr/bin/nm-env-prepare.sh"
COPY data-motd /etc/motd

RUN sed 's/.*RateLimitBurst=.*/RateLimitBurst=0/' /etc/systemd/journald.conf -i

RUN echo -e '[logging]\nlevel=TRACE\ndomains=ALL,VPN_PLUGIN:TRACE\n' >> /etc/NetworkManager/conf.d/90-my.conf
RUN echo -e '[main]\nno-auto-default=*\ndebug=RLIMIT_CORE,fatal-warnings\n' >> /etc/NetworkManager/conf.d/90-my.conf
RUN echo -e '[device-veths-1]\nmatch-device=interface-name:d_*\nmanaged=0\n' >> /etc/NetworkManager/conf.d/90-my.conf
RUN echo -e '[device-veths-2]\nmatch-device=interface-name:net*\nmanaged=1\n' >> /etc/NetworkManager/conf.d/90-my.conf

RUN rm -rf /etc/NetworkManager/system-connections/*

RUN echo 'cd $BASEDIR_NM' >> /root/.bash_history
RUN echo 'nm-env-prepare.sh setup --idx 1' >> /root/.bash_history
RUN echo 'systemctl stop NetworkManager; /opt/test/sbin/NetworkManager --debug 2>&1 | tee -a /tmp/nm-log.txt' >> /root/.bash_history
RUN echo 'NM-log' >> /root/.bash_history
RUN echo 'NM-log /tmp/nm-log.txt' >> /root/.bash_history
RUN chmod 600 /root/.bash_history

RUN echo 'alias m="make -j 8"' >> /etc/bashrc.my
RUN echo 'alias n="ninja -C build"' >> /etc/bashrc.my
RUN echo '' >> /etc/bashrc.my
RUN echo '. /usr/share/git-core/contrib/completion/git-prompt.sh' >> /etc/bashrc.my
RUN echo 'PS1="\[\\033[01;36m\]\u@\h\[\\033[00m\]:\\t:\[\\033[01;34m\]\w\\\$(__git_ps1 \\" \[\\033[01;36m\](%s)\[\\033[00m\]\\")\[\\033[00m\]\$ "' >> /etc/bashrc.my
RUN echo '' >> /etc/bashrc.my
RUN echo 'if test "\$SHOW_MOTD" != 0; then' >> /etc/bashrc.my
RUN echo '  cat /etc/motd' >> /etc/bashrc.my
RUN echo '  export SHOW_MOTD=0' >> /etc/bashrc.my
RUN echo 'fi' >> /etc/bashrc.my

RUN echo -e '\n. /etc/bashrc.my\n' >> /etc/bashrc
EOF
}

###############################################################################

usage() {
    cat <<EOF
$0: build|run|exec|clean [--no-cleanup]
EOF
}

###############################################################################

container_image_exists() {
    podman image exists my:nm || return 1
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

    DOCKERFILE="$(mktemp --tmpdir="$BASEDIR" dockerfile.XXXXXX)"
    CLEANUP_FILES+=($DOCKERFILE)
    create_dockerfile "$DOCKERFILE" "$BASE_IMAGE"
    podman build --tag "$CONTAINER_NAME_REPOSITORY:$CONTAINER_NAME_TAG" -f "$DOCKERFILE"
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
        podman run --privileged \
            --name "$CONTAINER_NAME_NAME" \
            -d \
            -v "$BASEDIR_NM:$BASEDIR_NM:Z" \
            "${BIND_FILES[@]}" \
            "$CONTAINER_NAME_REPOSITORY:$CONTAINER_NAME_TAG"
    fi
}

do_exec() {
    do_run
    podman exec --workdir "$BASEDIR_NM" -it "$CONTAINER_NAME_NAME" bash
}

###############################################################################

CMD=exec
for (( i=1 ; i<="$#" ; )) ; do
    c="${@:$i:1}"
    i=$((i+1))
    case "$c" in
        --no-cleanup)
            DO_CLEANUP=0
            ;;
        build|run|exec|clean)
            CMD=$c
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "invalid argument #$i: $c"
            ;;
    esac
done

###############################################################################

test "$UID" != 0 || die "cannot run as root"

###############################################################################

case "$CMD" in
    clean|build|run|exec)
        do_$CMD
        ;;
    *)
        die "missing command, one of build|run|exec|clean"
        ;;
esac
