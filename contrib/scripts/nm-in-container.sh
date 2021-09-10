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

COPY data-nm-env-prepare.sh "/usr/bin/nm-env-prepare.sh"

RUN sed 's/.*RateLimitBurst=.*/RateLimitBurst=0/' /etc/systemd/journald.conf -i

RUN echo -e '[logging]\nlevel=TRACE\ndomains=ALL,VPN_PLUGIN:TRACE\n' >> /etc/NetworkManager/conf.d/90-my.conf
RUN echo -e '[device-veths-1]\nmatch-device=interface-name:d_*\nmanaged=0\n' >> /etc/NetworkManager/conf.d/90-my.conf
RUN echo -e '[device-veths-2]\nmatch-device=interface-name:net*\nmanaged=1\n' >> /etc/NetworkManager/conf.d/90-my.conf

RUN rm -rf /etc/NetworkManager/system-connections/*

RUN echo 'alias m="make -j 8"' >> /etc/bashrc.my
RUN echo 'alias n="ninja -C build"' >> /etc/bashrc.my
RUN echo '' >> /etc/bashrc.my
RUN echo '. /usr/share/git-core/contrib/completion/git-prompt.sh' >> /etc/bashrc.my
RUN echo 'PS1="\[\\033[01;36m\]\u@\h\[\\033[00m\]:\\t:\[\\033[01;34m\]\w\\\$(__git_ps1 \\" \[\\033[01;36m\](%s)\[\\033[00m\]\\")\[\\033[00m\]\$ "' >> /etc/bashrc.my

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
    podman exec -it "$CONTAINER_NAME_NAME" /bin/bash -c "cd \"$BASEDIR_NM\"; exec /bin/bash"
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
