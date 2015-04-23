# Path for dependencies installed locally
#export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig/

get_timestamp() {
    date --utc '+%Y%m%d-%H%M%S'
}
log_timestamp() {
    printf "%s%s %s -- %s\n" ">>" ">>" "$(get_timestamp)" "$*"
}
DATE="`get_timestamp`"
REPO=ssh://Jenkins-nm-user/var/lib/git/NetworkManager.git

MAKE_JOBS="-j $((3 * $(grep -c ^processor /proc/cpuinfo || echo 1)))"

ulimit -c unlimited
export NMTST_DEBUG="no-debug,sudo-cmd=$PWD/tools/test-sudo-wrapper.sh"

git_notes() {
    if [[ "$GIT_NOTES_DISABLED" == true ]]; then
        return 0
    fi

    git fetch "$REPO" +refs/notes/test:refs/notes/test || git update-ref -d refs/notes/test

    # git-notes append adds a newline so merge them by hand...
    NOTE="$(git notes --ref=test show HEAD 2>/dev/null || true)"
    if [[ "x$NOTE" != "x" ]]; then
        newline='
'
        if [[ "${NOTE#"${NOTE%?}"}" != "$newline" ]]; then
            NOTE="$NOTE$newline"
        fi
    fi

    git notes --ref test add -f -m "$NOTE$1" HEAD
    git push "$REPO" refs/notes/test:refs/notes/test
}

join() {
    local IFS="$1"
    shift
    echo "$*"
}

git_notes_flags() {
    local FLAGS=()
    if [[ "$OUT_OF_TREE_BUILD" == true ]]; then
        FLAGS=("${FLAGS[@]}" "+O")
    else
        FLAGS=("${FLAGS[@]}" "-O")
    fi
    if [[ "$NO_CHECK" == true ]]; then
        FLAGS=("${FLAGS[@]}" "-C")
    else
        FLAGS=("${FLAGS[@]}" "+C")
    fi
    if [[ "$DISTCHECK" == true ]]; then
        FLAGS=("${FLAGS[@]}" "+D")
    elif [[ "$DIST" == true ]]; then
        FLAGS=("${FLAGS[@]}" "+d")
    else
        FLAGS=("${FLAGS[@]}" "-D")
    fi
    if [[ "$RPM" == true ]]; then
        FLAGS=("${FLAGS[@]}" "+R")
    else
        FLAGS=("${FLAGS[@]}" "-R")
    fi
    join ' ' "${FLAGS[@]}"
}

git_notes_ok() {
    git_notes "Tested: OK   $DATE $BUILD_URL $(git_notes_flags)"
}
git_notes_fail() {
    git_notes "Tested: FAIL $DATE $BUILD_URL $(git_notes_flags)"
}

trap "git_notes_fail; exit 1" ERR



temporary_workaround_01() {
    # https://bugzilla.gnome.org/show_bug.cgi?id=705160
    # otherwise current mem leaks check fail...
    if [[ "$(git merge-base 2540966492340ad87cd5a894d544580b8e20c558 HEAD 2>/dev/null || true)" != "2540966492340ad87cd5a894d544580b8e20c558" ]]; then
        wget 'https://bugzilla.gnome.org/attachment.cgi?id=256245' -O valgrind.suppressions.patch
        git apply valgrind.suppressions.patch || true
    fi
}

clean_all() {
    git reset --hard HEAD
    git clean -fdx
    git submodule foreach git reset --hard HEAD
    git submodule foreach git clean -fdx
    git submodule update

    temporary_workaround_01
}


if [[ "$OUT_OF_TREE_BUILD" == true ]]; then
    log_timestamp "out-of-tree: start"
    clean_all

    log_timestamp "out-of-tree: autogen"
    ./autogen.sh
    make distclean

    mkdir _build
    pushd _build
        log_timestamp "out-of-tree: configure"
        ../configure --enable-maintainer-mode --prefix=$PWD/.INSTALL/ --with-dhclient=yes --with-dhcpcd=yes --with-crypto=nss --enable-more-warnings=error --enable-ppp=yes --enable-polkit=yes --with-session-tracking=systemd --with-suspend-resume=systemd --with-tests=yes --enable-tests=yes --with-valgrind=yes --enable-ifcfg-rh=yes --enable-ifupdown=yes --enable-ifnet=yes --enable-gtk-doc --enable-qt=yes --with-system-libndp=no --enable-static=libndp --enable-bluez4=no --enable-wimax=no --enable-vala=no --enable-modify-system=no --enable-more-asserts --enable-more-logging
        log_timestamp "out-of-tree: make"
        make $MAKE_JOBS
    popd

    log_timestamp "out-of-tree: end"
fi

log_timestamp "build: start"
clean_all

log_timestamp "build: autogen.sh"
./autogen.sh --enable-maintainer-mode --prefix=$PWD/.INSTALL/ --with-dhclient=yes --with-dhcpcd=yes --with-crypto=nss --enable-more-warnings=error --enable-ppp=yes --enable-polkit=yes --with-session-tracking=systemd --with-suspend-resume=systemd --with-tests=yes --enable-tests=yes --with-valgrind=no --enable-ifcfg-rh=yes --enable-ifupdown=yes --enable-ifnet=yes --enable-gtk-doc --enable-qt=yes --with-system-libndp=no --enable-static=libndp --enable-bluez4=no --enable-wimax=no --enable-vala=no --enable-modify-system=no --enable-more-asserts --enable-more-logging

log_timestamp "build: make"
make $MAKE_JOBS

if [[ "$NO_CHECK" != true ]]; then
    log_timestamp "build: make check"
    make check
fi

if [[ "$DISTCHECK" == true ]]; then
    log_timestamp "distcheck: start"
    make distcheck
    log_timestamp "distcheck: end"
elif [[ "$DIST" == true || "$RPM" == true ]]; then
    log_timestamp "dist: start"
    make dist
    log_timestamp "dist: end"
fi


if [[ "$RPM" == true ]]; then
    log_timestamp "rpm: start"
    wget http://file.brq.redhat.com/~thaller/nmtui-0.0.1.tar.xz
    if [[ "$(git merge-base dd3d5b22207e63ecbfd7f2222435fdc691f66f2e HEAD 2>/dev/null || true)" != "dd3d5b22207e63ecbfd7f2222435fdc691f66f2e" ]]; then
        # in the meantime, the rpm build script merged to master.
        git checkout origin/automation -- :/contrib/
    fi
    ./contrib/fedora/rpm/build.sh
    log_timestamp "rpm: finished"
fi


log_timestamp "all finished with success"
git_notes_ok

