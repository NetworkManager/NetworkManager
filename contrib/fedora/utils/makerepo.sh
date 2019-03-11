#!/bin/bash

#
# The script is ugly but is here to help to create a git-repository
# based on dist-git.
#
#  * Works with fedpkg and rhpkg
#  * Different packages are supported. See detect_build_type below.
#  * Creates first an initial commit of the source directory (after "fedpkg prep")
#  * Excludes files and creates a gitignore file. It does so by .git/makerepo.gitignore
#    which can be edited manually. Also, after a `$0 local`, it will record all files
#    with modifications to be ignored in the future.
#  * Revert each patch from the spec file
#  * Reapply each patch until you are where were originally (sans ignored files)
#  * Restore again the original state, i.e. replying the patches (including ignored
#    files -- that are no longer part of master-tip).
#  * Fetch from upstream origin (and add as remote)
#  * Fetch from a local git repository (and add as remote)
#  * It can detect the parent commit where the package branched of
#    and rebase the created history on top of that.
#  * optionally, do `fedpkg local`.
#
# ONE-TIME SETUP:
#   - clone the dist-git package
#       $ PACKAGE=libnl3
#       $ fedpkg clone $PACKAGE
#       $ cd $PACKAGE
#
#   - configure local git-repository (optional)
#       $ ln -s /path/to/local/clone .git/local
#
#   - create initial gitignore file (optional)
#       $ edit .git/makerepo.gitignore
#     or
#       $ edit .git/makerepo.gitignore.$BRANCHNAME
#
# USAGE:
#       $ cd $PACKAGE
#       $ makerepo.sh
#       $ makerepo.sh local
#


#set -vx

die() {
	echo "$@" >&2
	exit 1
}

containsElement () {
    local e
    local name="$1"
    shift
    local i=0

    for e in "${@:2}"; do
        if [[ "$e" == "$1" ]]; then
            eval "$name=$i"
            return 0;
        fi
        i=$((i+1))
    done
    return 1
}

git_remote_add_gnome() {
    git remote add "${2-origin}" "https://gitlab.gnome.org/GNOME/$1.git" && \
    git remote 'set-url' --push "${2-origin}" "git@gitlab.gnome.org:GNOME/$1.git"
}

git_remote_add_github() {
    git remote add "${2-origin}" "git://github.com/$1.git"
    git remote 'set-url' --push "${2-origin}" "git@github.com:$1.git"
}

srcdir="$(readlink -f "$(git rev-parse --show-toplevel 2>/dev/null)")"
[[ "x$srcdir" != x ]] || die "Could not detect dist-git directory (are you inside the git working directory?)"
cd "$srcdir" || die "Could not switch to dist-git directory"


if [[ "x$(ls -1d ./*.spec 2>/dev/null)" == x || ! -f "./sources" ]]; then
    die "**Error**: Directory "\`$srcdir\'" does not look like the dist-git pkg dir."
fi

if [[ "$FEDPKG" == "" ]]; then
    REMOTES="$(git remote -v 2>/dev/null)" || die "not inside dist-git repository? >>$PWD<<"
    if echo "$REMOTES" | grep -q -F 'pkgs.devel.redhat.com' ; then
        FEDPKG=rhpkg
    else
        FEDPKG=fedpkg
    fi
fi

split_patch() {
    # patches created with git-format-patch that contain more then one
    # commit, cannot be easily reverted with patch, because patch works
    # the patches from top down. In case of -R however, we have to apply
    # the latest patches first.

    read -r -d '' PERL_PROG <<-'EOF'
		use strict;
		use warnings;

		open FILE, $ARGV[0]  or die "Can't open $ARGV[0] for reading: $!\n";

		local $/ = undef;
		my $file = <FILE>;
		close FILE;

		my @patches = split(/\n\nFrom /,$file);

		my $i = $#patches + 1;
		my $patch;
		my $first = 1;
		foreach $patch (@patches){
			if ($first) {
				$first = 0;
			} else {
				$patch = "From $patch"
			}
			my $o = sprintf("%s%s%03d", $ARGV[0], $ARGV[1], $i);
			open(my $OUT, ">", $o) or die "Can't open $o for writing: $!";
			$i--;

			print $OUT "$patch";

			close $OUT;
		}
	EOF

    perl -e "$PERL_PROG" "$1" "$2"
}

spec_parse_patch_p() {
    local SPEC="$1"
    local NUM="$2"

    local P="$(sed -n "s/^%\<patch$NUM\>.* -p\([0-9]\+\) .*$/\1/p" "$SPEC")"

    echo "${P:-1}"
}

get_patch_origin() {
    local PATCH="$1"

    (
        cd "$srcdir"

        local HASH="$(git log -n1 --format="%H" HEAD -- "$PATCH")"

        if [[ "$HASH" == "" ]]; then
            return
        fi

        printf "\n\nPatch \"%s\" was last modified in commit:\n\n" "$PATCH"
        git log -n1 "$HASH" | sed 's/^[^ ]/    \0/'
    )
}

print_synopsis() {
    echo "SYNOPSIS: $(basename "$0") [--dist|-d DIST] [local|--local|-l] [-?|-h|--help|help] [NUM]"
    echo "  - If [NUM] is omitted, it will revert all patches from the spec file,"
    echo "    otherwise only the last NUM patches."
    echo "  - When specifying 'local', it will also call \`$FEDPKG local\` to configure"
    echo "    and build the output directory."
    echo "  - '--dist' implies '--local'. This argument is passed to ${FEDPKG}."
    echo "  TIP: symlink your local git clone of upstream to './.git/local'."
}

unset REVERT_COUNT
LOCAL=0
DIST=""
while [ $# -ne 0 ]; do
    ARG="$1"
    shift
    case "$ARG" in
        -h|'-?'|help|--help)
            print_synopsis
            exit 0
            ;;
        local|--local|-l)
            LOCAL=1
            ;;
        --dist|-d)
            DIST="$1"
            shift
            if [ "x$DIST" = x ]; then
                print_synopsis
                die "--dist needs an argument"
            fi
            ;;
        *)
            if [ -n "${REVERT_COUNT+x}" ]; then
                print_synopsis
                die "invalid argument \"$ARG\""
            fi
            case "$ARG" in
                ''|*[!0-9]*)
                    print_synopsis
                    die "invalid argument \"$ARG\": should be an integer (number of patches to revert)"
                    ;;
            esac
            REVERT_COUNT="$ARG"
            ;;
    esac
done

if [ "x$DIST" != x ]; then
    DIST=" --dist $DIST"
fi

# generate the clean dir
$FEDPKG $DIST prep || die "error while \`$FEDPKG$DIST prep\`"

detect_build_type() {
    local TEST_DIR="./$1/"
    local TEST_SPEC="$2"
    local TEST_BUILD_TYPE="$3"
    local DIRNAME

    if [[ -n "$BUILD_TYPE" || -z "$1" || "x$(ls -1d $TEST_DIR 2>/dev/null)" == x || ! -f "$TEST_SPEC" ]]; then
        return 1
    fi

    DIRNAME="$(ls -1d $TEST_DIR)" || die "could not find directory"
    DIRNAME="$(basename "$DIRNAME")"
    SPEC="$TEST_SPEC"

    if [[ -n "$TEST_BUILD_TYPE" ]]; then
        BUILD_TYPE="$TEST_BUILD_TYPE"
    else
        BUILD_TYPE="${TEST_SPEC%.spec}"
    fi
}

detect_dirname() {
    local BUILD_TYPE="$1"
    local DIRS=()
    local SOURCES
    local D suffix T

    SOURCES="$(sed 's/^\(SHA512 (\(.*\)) = [0-9a-f]\{128\}\|\([0-9a-f]\{32\} \+\(.*\)\)\)$/\2\4/' ./sources 2>/dev/null)"

    for suffix in .tar.gz .tar.bz .tar.xz .tgz .tar.bz2 ; do
        for T in ${SOURCES[@]}; do
            if [[ "$T" == *$suffix ]]; then
                D="${T%$suffix}"
                [[ -d "$D" ]] && DIRS=("${DIRS[@]}" "$D")
                D="$(tar -tf "$T" | sed 's#/.*##' | sort | uniq)"
                [[ -d "$D" ]] && DIRS=("${DIRS[@]}" "$D")
            fi
        done

        # iterate over all tarballs that start with "$BUILD_TYPE" and
        # see if there exists a directory with the same name as
        # the unpacked tarball (that is, stripping the suffix).
        for T in $(ls -1 "$BUILD_TYPE"*"$suffix" 2>/dev/null); do
            D="${T%$suffix}"
            [[ -d "$D" ]] && DIRS=("${DIRS[@]}" "$D")
        done
    done

    D=
    if [[ ${#DIRS[@]} -ge 1 ]]; then
        # return the newest directory.
        D="$(ls -1d --sort=time --time=ctime "${DIRS[@]}" 2>/dev/null | head -n1)"
    fi
    if [[ "$D" != "" ]]; then
        printf "%s" "$D"
        return 0
    fi
    return 1
}

BUILD_TYPE=
detect_build_type 'NetworkManager-[0-9]*' NetworkManager.spec
detect_build_type 'network-manager-applet-[0-9]*' network-manager-applet.spec
detect_build_type 'libnl-[0-9]*' libnl3.spec
detect_build_type 'NetworkManager-openvpn-[0-9]*' NetworkManager-openvpn.spec
detect_build_type 'NetworkManager-openswan-[0-9]*' NetworkManager-openswan.spec
detect_build_type 'NetworkManager-libreswan-[0-9]*' NetworkManager-libreswan.spec
detect_build_type 'NetworkManager-vpnc-[0-9]*' NetworkManager-vpnc.spec
detect_build_type 'ModemManager-[0-9]*' ModemManager.spec
detect_build_type 'wireless_tools.[0-9]*' wireless-tools.spec
detect_build_type 'umip-[0-9]*' mipv6-daemon.spec
detect_build_type 'initscripts-[0-9]*' initscripts.spec
detect_build_type 'libqmi-[0-9]*' libqmi.spec
detect_build_type 'libibverbs-[0-9]*' libibverbs.spec
detect_build_type 'iproute2-*' iproute.spec
detect_build_type 'glib-2*' glib2.spec
detect_build_type 'vpnc-*' vpnc.spec
detect_build_type 'gnome-control-center-*' control-center.spec gnome-control-center

if [[ -z "$BUILD_TYPE" ]]; then
    SPEC="$(ls -1 *.spec 2>/dev/null | head -n1)"
    BUILD_TYPE="${SPEC%.spec}"
    [[ -n "$BUILD_TYPE" ]] || die "Failed to detect repository type (no spec file)"

    [[ -f sources ]] || die "Failed to detect repository type (no sources file)"
fi

DIRNAME="$(detect_dirname "$BUILD_TYPE")" || die "Failed to detect repository type (no directory)."

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null)"
if [[ "x$CURRENT_BRANCH" != x && -f "./.git/makerepo.gitignore-$CURRENT_BRANCH" ]]; then
    MAKEREPO_GIT_IGNORE_MY="makerepo.gitignore-$CURRENT_BRANCH"
elif [[ -f ./.git/makerepo.gitignore ]]; then
    MAKEREPO_GIT_IGNORE_MY=makerepo.gitignore
else
    MAKEREPO_GIT_IGNORE_MY=""
fi
MAKEREPO_GIT_IGNORE_LAST="makerepo.gitignore.last-$CURRENT_BRANCH"

get_local_mirror() {
    local URL="$1"

    if [[ -z "$URL" ]]; then
        return
    fi

    local DIRNAME="$(echo $URL.git | sed -e 's#^.*/\([^/]\+\)$#\1#' -e 's/\(.*\)\.git$/\1/')"
    local FULLNAME="$srcdir/.git/.makerepo-${DIRNAME}.git"

    [[ -n "$NO_REMOTE" ]] && return

    if [[ ! -d "$FULLNAME" ]]; then
        if [[ -f "$FULLNAME" ]]; then
            # create a file with name $FULLNAME, to suppress local mirroring
            return
        fi
        git clone --mirror --bare "$URL" "$FULLNAME/"
    fi
    (
        cd "$FULLNAME"
        git fetch origin --prune
        git gc
    )
    echo "$FULLNAME"
}

pushd "$DIRNAME"
    git init .
    # if you have a local clone of upstream, symlink it as ../.git/local.
    if [[ "$BUILD_TYPE" == "NetworkManager" ]]; then
        git remote add origin "https://gitlab.freedesktop.org/NetworkManager/NetworkManager.git"
        git remote 'set-url' --push origin "git@gitlab.freedesktop.org:NetworkManager/NetworkManager.git"
        git config notes.displayRef refs/notes/bugs
        git config --add remote.origin.fetch refs/tags/*:refs/tags/*
        git config --add remote.origin.fetch refs/notes/bugs:refs/notes/bugs
    elif [[ "$BUILD_TYPE" == "ModemManager" ]]; then
        git remote add origin "git://anongit.freedesktop.org/ModemManager/ModemManager"
        git remote 'set-url' --push origin "ssh://$USER@git.freedesktop.org/git/ModemManager/ModemManager"
        git config --add remote.origin.fetch refs/tags/*:refs/tags/*
    elif [[ "$BUILD_TYPE" == "libnl3" ]]; then
        git_remote_add_github thom311/libnl
    elif [[ "$BUILD_TYPE" == "network-manager-applet" ||
            "$BUILD_TYPE" == "gnome-control-center" ||
            "$BUILD_TYPE" == "NetworkManager-fortisslvpn" ||
            "$BUILD_TYPE" == "NetworkManager-libreswan" ||
            "$BUILD_TYPE" == "NetworkManager-openconnect" ||
            "$BUILD_TYPE" == "NetworkManager-openvpn" ||
            "$BUILD_TYPE" == "NetworkManager-pptp" ||
            "$BUILD_TYPE" == "NetworkManager-vpnc" ]]; then
        git_remote_add_gnome "$BUILD_TYPE"
    elif [[ "$BUILD_TYPE" == "glib2" ]]; then
        git_remote_add_gnome glib
    elif [[ "$BUILD_TYPE" == "NetworkManager-openswan" ]]; then
        git remote add origin "git://git.gnome.org/network-manager-openswan";
        git remote 'set-url' --push origin "ssh://$USER@git.gnome.org/git/network-manager-openswan"
    elif [[ "$BUILD_TYPE" == "wpa_supplicant" ]]; then
        git remote add origin "git://w1.fi/hostap.git"
        git_remote_add_github NetworkManager/hostap nm
    elif [[ "$BUILD_TYPE" == "mipv6-daemon" ]]; then
        git remote add origin "git://git.umip.org/umip.git";
    elif [[ "$BUILD_TYPE" == "libqmi" ]]; then
        git remote add origin 'git://anongit.freedesktop.org/libqmi';
    elif [[ "$BUILD_TYPE" == "libibverbs" ]]; then
        git remote add origin 'git://git.kernel.org/pub/scm/libs/infiniband/libibverbs.git';
    elif [[ "$BUILD_TYPE" == "initscripts" ]]; then
        git remote add origin "https://git.fedorahosted.org/git/initscripts.git";
    elif [[ "$BUILD_TYPE" == "iproute" ]]; then
        git remote add origin "git://git.kernel.org/pub/scm/linux/kernel/git/shemminger/iproute2.git"
    elif [[ "$BUILD_TYPE" == "vpnc" ]]; then
        git_remote_add_github ndpgroup/vpnc
    fi
    LOCAL_MIRROR_URL="$(LANG=C git remote -v | sed -n 's/^origin\t*\([^\t].*\) (fetch)/\1/p')"
    LOCAL_MIRROR="$(get_local_mirror "$LOCAL_MIRROR_URL")"
    if [[ -n "$LOCAL_MIRROR" ]]; then
        git remote add local-mirror "$LOCAL_MIRROR"
        git fetch local-mirror
    fi
    LOCAL_GIT="$(readlink -f ../.git/local/)"
    if [[ -d "$LOCAL_GIT" ]]; then
        git remote add local "$LOCAL_GIT/"
        git fetch local
    fi
    if [[ "$(git remote | grep '^origin$')x" != x && -z "$NO_REMOTE" ]]; then
        git fetch origin
        if [[ -n "$LOCAL_MIRROR" ]]; then
            git remote rm local-mirror
        fi
    fi
    git commit --allow-empty -m '*** empty initial commit'  # useful, to rebase the following commit
    git add -f -A .
    git commit -m '*** add all'
    git tag -f ALL
    ORIG_HEAD="`git rev-parse HEAD`"
    if [[ "x$RELEASE_BASE_COMMIT" == x ]]; then
        # if RELEASE_BASE_COMMIT is not set, try detecting the BASE_COMMIT...

        if [[ "$BUILD_TYPE" == "NetworkManager" ||
              "$BUILD_TYPE" == "NetworkManager-fortisslvpn" ||
              "$BUILD_TYPE" == "NetworkManager-libreswan" ||
              "$BUILD_TYPE" == "NetworkManager-pptp" ||
              "$BUILD_TYPE" == "NetworkManager-openconnect" ||
              "$BUILD_TYPE" == "NetworkManager-vpnc" ]]; then
            RELEASE_BASE_COMMIT="$(sed -n 's/^NM_GIT_SHA=\(.*\)/\1/p' configure 2>/dev/null)"
        elif [[ "$BUILD_TYPE" == "libnl3" ]]; then
            RELEASE_BASE_COMMIT="$(sed -n 's/^LIBNL_GIT_SHA=\(.*\)/\1/p' configure 2>/dev/null)"
            if [[ "$RELEASE_BASE_COMMIT" == "23c44dad998f72f39fd1fc24aa9579fd0a7f05c0" ]]; then
                RELEASE_BASE_COMMIT="e01b9df629e2f4f833fdc4fe0bda460bb738d136"
            fi
        elif [[ "$BUILD_TYPE" == "network-manager-applet" ]]; then
            RELEASE_BASE_COMMIT="$(sed -n 's/^NMA_GIT_SHA=\(.*\)/\1/p' configure 2>/dev/null)"
            if [[ "$RELEASE_BASE_COMMIT" == "8d8e34f22d5fae476eda96cf36d828c3ae8b63d3" ]]; then
                RELEASE_BASE_COMMIT="a2377d7534780b96a32405cce2e5548e81bbd081"
            fi
        elif [[ "$BUILD_TYPE" == "glib2" ]]; then
            RELEASE_BASE_COMMIT="$(git rev-parse --verify -q "$(sed 's/.*\<glib-\([0-9]\+\.[0-9]\+\.[0-9]\+\)\.[a-z0-9_.]\+ *$/\1/' ../sources)^{commit}" 2>/dev/null)"
        elif [[ "$BUILD_TYPE" == "iproute" ]]; then
            RELEASE_BASE_COMMIT="$(git rev-parse --verify -q "$(sed 's/.*\<iproute2-\([0-9]\+\.[0-9]\+\.[0-9]\+\)\..*/v\1/' ../sources)^{commit}" 2>/dev/null)"
        elif [[ "$BUILD_TYPE" == "NetworkManager-openvpn" ]]; then
            RELEASE_BASE_COMMIT="$(sed -n 's/^NM_GIT_SHA=\(.*\)/\1/p' configure 2>/dev/null)"
            if [[ "x$RELEASE_BASE_COMMIT" == x ]]; then
                DATE="$(sed -n 's/%global snapshot .git\(20[0-3][0-9]\)\([0-1][0-9]\)\([0-3][0-9]\)/\1-\2-\3/p' "../$SPEC")"
                if [[ "x$DATE" != x ]]; then
                    RELEASE_BASE_COMMIT="$(git rev-list -n1 --date-order --before="$DATE" origin/master 2>/dev/null)"
                fi
            fi
        fi
        if [[ "x$RELEASE_BASE_COMMIT" == x ]]; then
            KNOWN_BASE_COMMITS="$(cat <<EOF
# NetworkManager
08670c9163a5d0f15c57c7891ef899eb125d9423  7251704430cb206f2c29bfebc45bd0fb *NetworkManager-0.9.9.0.git20131003.tar.bz2

# ModemManager
397761c9758c3a8c2d130afaf36dab645d6e0ecf  d9d93d2961ee35b4cd8a75a6a8631cb4  ModemManager-1.6.0.tar.xz
b23413a064f03fb2f2214fb32164bcb4b7037c45  67160b94c0eda90ebf95d1b620229ca1  ModemManager-1.6.10.tar.xz

# libnl3
1a510c57e905c4beb06122b9688162c82d9b044f  d1111959652bd6ad87b2071f61c8c20c *libnl-doc-3.2.24.tar.gz
83c762d7cf6a6c54831e8d684b22804f497704c4  6fe7136558a9071e70673dcda38545b3 *libnl-3.2.21.tar.gz
c4d846f239036c05f516c1c71789e980b64b1e70  2e1c889494d274aca24ce5f6a748e66e *libnl-3.2.22.tar.gz
0446731124bea8c1b447cc52a5ad5ae5750810ff  636769646f5b81b0caead81eab151b45 *libnl-3.2.25-rc1.tar.gz
bd0e87b3d81d2498c3f35d5497771828bf04e017  e34999eaa184c84b315a8dff8afa4219  libnl-3.2.28-rc1.tar.gz
656f381ccf58785319bb0236595c896125d33ed0  bab12db1eb94a42129f712a44be91a67  libnl-3.2.28.tar.gz

# NetworkManager-applet
5d4f17e205f71972d4143f9760426a366b4129d7  9cc0e383c216d4bc31622a0cfb53aaa7 *network-manager-applet-0.9.9.0.git20140123.5d4f17e.tar.bz2
36c868498f09eacafcdce9d6b68ca5aeffaae899  3146f3ac3c30996a96cd2c602fbc81e1 *network-manager-applet-0.9.10.3.git20150511.36c8684.tar.bz2
2d5b36cf69ea6d5e11726d479012c8ad7d6fd9fc  7fc2ed3f0c46ed41ddabe99d51513b1c *network-manager-applet-1.0.4.tar.xz

# NetworkManager-libreswan, NetworkManager-openswan
64c90fd50e57854a3fff3784b92814ffa8159b05  6a373868f85ac3b7c953f7fd6c76e637 *NetworkManager-openswan-0.9.8.0.tar.xz
78555150e4df29eb39fa4a105f884f53b0f4523f  df9144805f37dc30dfaeab8da762f615 *NetworkManager-openswan-1.0.6.tar.xz
3ef831cf25e86675f9838bf58b1cd6e592c6e14f  01248eb95a1e1d647057a45aed85a3af *NetworkManager-libreswan-1.2.4.tar.xz

# NetworkManager-vpnc
89bdcd324f2e257eca59168a7d0be5608438aab0  abb26a6c3c8d6c1d91c78471aff86b3a *NetworkManager-vpnc-0.9.8.2.tar.xz
c37a79d43ebe1192ba8dcc5036cd668631b6473e  d87db7021629cef7c110a371dd42b7a8 *NetworkManager-vpnc-0.9.9.0.git20140131.tar.bz2
68ca41550f9289835ea9d80e1ee059322ebe749a  4c16379738264a117d09c171c645ff23 *NetworkManager-vpnc-1.2.2.tar.xz

# NetworkManager-openvpn
1f159f30617e4a3b8121074b8bf238312941370d  511eae0d4ac17c6d2659a3da2646296f *NetworkManager-openvpn-1.0.2.tar.xz
75585a94b394c04e45a28d2b032fe83dcdaeebee  ee4c09a8896eab3e1740f7c7bc1434f9  NetworkManager-openvpn-1.2.4.tar.xz

# mipv6-daemon
428974c2d0d8e75a2750a3ab0488708c5dfdd8e3  8e3ebd242e7926822bbdf5ce77c1d076 *mipv6-daemon-1.0.tar.gz

# libqmi
7d688f382f9756027bf92338e413e425365d2835  17d6c2b404ee1eb4d1e60050fef64491 *libqmi-1.6.0.tar.xz

# gnome-control-center
e87e0361b117f055ace2aa47cdddd0dc62a852f9  da949e268254af6aafdda0e8c1702384 *gnome-control-center-3.22.1.tar.xz

# wpa_supplicant
22760dd94722a61175ff90c59d88c4cda1ed5e23  3be2ebfdcced52e00eda0afe2889839d *wpa_supplicant-2.0.tar.gz

# libibverbs
990ca025d0ad967b6f266bae700bf82a4ceaff1a  1fe85889c8bbc4968b1feba6524ca408 *libibverbs-1.1.8.tar.gz

# initscripts
cc304f05edab6c408a0f061eb1a104f9f06b8587  86ef789876b65c61751ce854835b91d4  initscripts-9.49.35.tar.bz2
EOF
)"
            OLDIFS="$IFS"
            IFS=$'\n'
            for KNOWN_BASE_COMMIT in $KNOWN_BASE_COMMITS; do
                MATCH="$(echo "$KNOWN_BASE_COMMIT" | sed -n 's/^[0-9a-f]\{40\} \+\(.*\)$/\1/p')"
                if [[ "x$MATCH" == x ]]; then
                    continue
                fi
                if grep -q "$MATCH" ../sources; then
                    RELEASE_BASE_COMMIT="$(echo "$KNOWN_BASE_COMMIT" | awk '{print $1}')"
                    break
                fi
            done
            IFS="$OLDIFS"
        fi
    fi
    if [[ x != "x$RELEASE_BASE_COMMIT" ]]; then
        if [[ "$RELEASE_BASE_COMMIT" == "-" ]]; then
            # you can disable detection of the RELEASE_BASE_COMMIT by setting it to '-'
            RELEASE_BASE_COMMIT=
        else
            # verify the base commit...
            RELEASE_BASE_COMMIT2="$(git rev-parse --verify -q "$RELEASE_BASE_COMMIT^{commit}" 2>/dev/null)"
            [[ x == "x$RELEASE_BASE_COMMIT2" ]] && test -z "$NO_REMOTE" && die "error detecting RELEASE_BASE_COMMIT=$RELEASE_BASE_COMMIT"
            RELEASE_BASE_COMMIT="$RELEASE_BASE_COMMIT2"
        fi
    fi
    if [[ x != "x$RELEASE_BASE_COMMIT" ]]; then
        git checkout -B master "$RELEASE_BASE_COMMIT" || die "could not checkout master"
        git tag -f BASE
        git rm --cached -r :/
        git checkout "$ORIG_HEAD" -- :/
        git clean -fdx :/
        git commit -m '*** add all'
        git tag -f ALL
        [[ x == "x$(git diff HEAD "$ORIG_HEAD")" ]] || die "error recreating initial tarball"
    fi
    (
        if [[ -n "$MAKEREPO_GIT_IGNORE_MY" ]]; then
            cat "../.git/$MAKEREPO_GIT_IGNORE_MY"
        fi
        if [[ -f "../.git/$MAKEREPO_GIT_IGNORE_LAST" ]]; then
            cat "../.git/$MAKEREPO_GIT_IGNORE_LAST"
        fi
        sed -n 's/^%patch\([0-9]\+\) \+.*-b \+\([^ ]\+\).*$/*\2/p' ../"$SPEC";
        echo '*.[0-9][0-9][0-9][0-9][-.]*.orig'
    ) | LANG=C sort | LANG=C uniq > .gitignore

    git rm --cached -r .
    git add --all .
    git commit -m "*** clean state (ignored files removed)"
    git tag -f CLEAN

    if [[ "$REVERT_COUNT" == "" || $REVERT_COUNT -gt 0 ]]; then

        # parse the list of patches
        IFS=$'\n' read -rd '' -a PATCH_LIST <<<"$(sed -n 's/^Patch\([0-9]\+\): \+\(.*\)$/\1 \2/p' ../"$SPEC" | sort -n)"

        if [[ "$BUILD_TYPE" == "NetworkManager" ]]; then
            if containsElement idx "123 rh1085015-applet-translations.patch" "${PATCH_LIST[@]}"; then
                # for rhel-6, NetworkManager contains some patches that break the script. In this
                # case, truncate the list of what we would normally revert.
                PATCH_LIST=("${PATCH_LIST[@]:$((idx+1))}")
            fi
        fi

        # truncate the list of patches to revert/reapply
        if [[ "$REVERT_COUNT" == "" || "$REVERT_COUNT" -gt ${#PATCH_LIST[@]} ]]; then
            echo "revert all ${#PATCH_LIST[@]} patches"
        else
            echo "revert the last $REVERT_COUNT patches of ${#PATCH_LIST[@]}"
            PATCH_LIST=("${PATCH_LIST[@]:$((${#PATCH_LIST[@]} - $REVERT_COUNT))}")
        fi

        # split the list in index and patch file name
        PATCH_LIST_N=()
        for i in ${!PATCH_LIST[@]}; do
            LAST_PATCH_N[$i]=$(echo "${PATCH_LIST[$i]}" | sed -n 's/^\([0-9]\+\) \+.*$/\1/p')
            LAST_PATCH[$i]=$(  echo "${PATCH_LIST[$i]}" | sed -n 's/^\([0-9]\+\) \+\(.*\)$/\2/p')
        done

        # revert and patches in reverse order...
        BASECOMMIT=("`git rev-parse HEAD`")
        for j in "${!PATCH_LIST[@]}"; do
            i=$((${#PATCH_LIST[@]} - $j - 1))
            echo "revert Patch${LAST_PATCH_N[$i]} \"${LAST_PATCH[$i]}\"..."
            PNUM="$(spec_parse_patch_p "../$SPEC" "${LAST_PATCH_N[$i]}")"
            patch -f --no-backup-if-mismatch -R "-p$PNUM" < "../${LAST_PATCH[$i]}" || (
                # error applying patch. Maybe we have a multi line patch...

                rm -f "../${LAST_PATCH[$i]}".makerepo-split.*
                split_patch "../${LAST_PATCH[$i]}" ".makerepo-split."

                git reset --hard
                git clean -fdx
                for p in "../${LAST_PATCH[$i]}".makerepo-split.*; do
                    echo ">>> try split part $p for ${LAST_PATCH[$i]}"
                    patch --no-backup-if-mismatch -R "-p$PNUM" < "$p" || die "error reverting Patch${LAST_PATCH_N[$i]} ${LAST_PATCH[$i]}"
                done
            )
            git add --all .
            git commit --allow-empty -a -m "<< revert Patch${LAST_PATCH_N[$i]} \"${LAST_PATCH[$i]}\"$(get_patch_origin "${LAST_PATCH[$i]}")"
            BASECOMMIT=("`git rev-parse HEAD`" "${BASECOMMIT[@]}")
            git tag -f REVERT"${LAST_PATCH_N[$i]}"
        done

        # reapply the patches
        for i in ${!PATCH_LIST[@]}; do
            echo "reapply Patch${LAST_PATCH_N[$i]} \"${LAST_PATCH[$i]}\"..."

            # create an empty commit, indicating the commit before starting to reapply
            BASECOMMIT_REVERT="${BASECOMMIT[$((i))]}"
            COMMIT_MSG="$(git log -n1 --format='%s%n%n%b' "$BASECOMMIT_REVERT" | sed '1s/<< revert \(Patch.*"\)$/-- before reapplying \1/')"
            git commit --allow-empty -m "$COMMIT_MSG"
            git tag -f "BEFORE_PATCH${LAST_PATCH_N[$i]}"
            git tag -f "LAST0"

            # first try git-am to preserve the commit message, otherwise just revert the last commit
            if git am "../${LAST_PATCH[$i]}"; then
                # The tree to the version before should be identical after reapplying the patch.
                # Just to be sure, reset the commit.
                git reset "${BASECOMMIT[$((i+1))]}" -- .
                COMMIT_MSG="$(git log -n1 --format='%s%n%n%b' "$BASECOMMIT_REVERT" | sed '1s/<< revert \(Patch.*"\)$/-- after reapplying \1\n\ngit-am did not fully restore the previous state/')"
                git commit -m "$COMMIT_MSG" || echo "NOTHING TO COMMIT"
            else
                git am --abort
                git reset "${BASECOMMIT[$((i+1))]}" -- .
                COMMIT_MSG="$(git log -n1 --format='%s%n%n%b' "$BASECOMMIT_REVERT" | sed '1s/<< revert \(Patch.*"\)$/>> reapply \1/')"
                git commit --allow-empty -m "$COMMIT_MSG"
            fi
            git reset --hard HEAD
            git clean -fdx
            [[ x = "x$(git diff "${BASECOMMIT[$((i+1))]}" HEAD)" ]] || die "error reverting patch"
            git tag -f PATCH"${LAST_PATCH_N[$i]}"
        done
        git tag -f LAST
    fi
    git checkout "$ORIG_HEAD" -- .
    git checkout HEAD~ -- .gitignore
    git reset

    git gc
popd

if [[ $LOCAL != 0 ]]; then
    rm -rf ./.makerepo.git/
    mv "$DIRNAME/.git" ./.makerepo.git/
    $FEDPKG $DIST local
    mv ./.makerepo.git/ "$DIRNAME/.git"
    pushd "$DIRNAME"
        git checkout -- .gitignore

        # write git-ignore file...
        git status --porcelain | sed 's/^...//' >> "../.git/$MAKEREPO_GIT_IGNORE_LAST"
    popd
fi

echo SUCCESS;
