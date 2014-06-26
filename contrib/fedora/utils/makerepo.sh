#!/bin/bash

#set -vx

die() {
	echo "$@" >&2
	exit 1
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

unset REVERT_COUNT
LOCAL=0
for ARG; do
    case "$ARG" in
        -h|-?|help|--help)
            echo "SYNOPSIS: $(basename "$0") [local|-l] [-?|-h|--help|help] [NUM]"
            echo "  - If [NUM] is omitted, it will revert all patches from the spec file,"
            echo "    otherwise only the last NUM patches."
            echo "  - When specifying 'local', it will also call \`$FEDPKG local\` to configure"
            echo "    and build the output directory."
            echo "  TIP: symlink your local git clone of upstream to './.git/local'."
            exit 0
            ;;
        local|-l)
            LOCAL=1
            ;;
        *)
            if [ -n "${REVERT_COUNT+x}" ]; then
                die "invalid argument \"$ARG\""
            fi
            case "$ARG" in
                ''|*[!0-9]*) die "invalid argument \"$ARG\": should be an integer (number of patches to revert)";;
            esac
            REVERT_COUNT="$ARG"
            ;;
    esac
done

# generate the clean dir
$FEDPKG prep || die "error while \`$FEDPKG prep\`"

if [[ "x$(ls -1d ./NetworkManager-[0-9].*/ 2>/dev/null)" != x && -f NetworkManager.spec ]]; then
    DIRNAME="$(basename "$(ls -1d ./NetworkManager-[0-9].*/ || die "could not find directory")")"
    BUILD_NETWORMANAGER=x
    SPEC=NetworkManager.spec
elif [[ "x$(ls -1d ./libnl-[0-9].*/ 2>/dev/null)" != x && -f libnl3.spec ]]; then
    DIRNAME="$(basename "$(ls -1d ./libnl-[0-9].*/ || die "could not find directory")")"
    BUILD_LIBNL3=x
    SPEC=libnl3.spec
elif [[ "x$(ls -1d ./NetworkManager-openvpn-[0-9].*/ 2>/dev/null)" != x && -f NetworkManager-openvpn.spec ]]; then
    DIRNAME="$(basename "$(ls -1d ./NetworkManager-openvpn-[0-9].*/ || die "could not find directory")")"
    BUILD_NETWORMANAGER_OPENVPN=x
    SPEC=NetworkManager-openvpn.spec
elif [[ "x$(ls -1d ./NetworkManager-openswan-[0-9].*/ 2>/dev/null)" != x && -f NetworkManager-openswan.spec ]]; then
    DIRNAME="$(basename "$(ls -1d ./NetworkManager-openswan-[0-9].*/ || die "could not find directory")")"
    BUILD_NETWORMANAGER_OPENSWAN=x
    SPEC=NetworkManager-openswan.spec
elif [[ "x$(ls -1d ./NetworkManager-openswan-[0-9].*/ 2>/dev/null)" != x && -f NetworkManager-libreswan.spec ]]; then
    DIRNAME="$(basename "$(ls -1d ./NetworkManager-openswan-[0-9].*/ || die "could not find directory")")"
    BUILD_NETWORMANAGER_LIBRESWAN=x
    SPEC=NetworkManager-libreswan.spec
else
    die "Could not detect dist-git type"
fi

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null)"
if [[ "x$CURRENT_BRANCH" != x && -f "./.git/makerepo.gitignore-$CURRENT_BRANCH" ]]; then
    /bin/cp "./.git/makerepo.gitignore-$CURRENT_BRANCH" ./makerepo.gitignore
elif [[ -f ./.git/makerepo.gitignore ]]; then
    /bin/cp "./.git/makerepo.gitignore" ./makerepo.gitignore
fi

get_local_mirror() {
    local URL="$1"

    if [[ -z "$URL" ]]; then
        return
    fi

    local DIRNAME="$(echo $URL.git | sed -e 's#^.*/\([^/]\+\)$#\1#' -e 's/\(.*\)\.git$/\1/')"
    local FULLNAME="$srcdir/.git/.makerepo-${DIRNAME}.git"

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
    if [[ "$BUILD_NETWORMANAGER" != "" ]]; then
        git remote add origin "git://anongit.freedesktop.org/NetworkManager/NetworkManager"
        git remote 'set-url' --push origin "ssh://$USER@git.freedesktop.org/git/NetworkManager/NetworkManager"
        git config notes.displayRef refs/notes/bugs
        git config --add remote.origin.fetch refs/tags/*:refs/tags/*
        git config --add remote.origin.fetch refs/notes/bugs:refs/notes/bugs
    elif [[ "$BUILD_LIBNL3" != "" ]]; then
        git remote add origin "git://github.com/thom311/libnl.git"
        git remote 'set-url' --push origin "git@github.com:thom311/libnl.git"
    elif [[ "$BUILD_NETWORMANAGER_OPENVPN" != "" ]]; then
        git remote add origin "git://git.gnome.org/network-manager-openvpn";
        git remote 'set-url' --push origin "ssh://$USER@git.gnome.org/git/network-manager-openvpn"
    elif [[ "$BUILD_NETWORMANAGER_OPENSWAN" != "" || "$BUILD_NETWORMANAGER_LIBRESWAN" != "" ]]; then
        git remote add origin "git://git.gnome.org/network-manager-openswan";
        git remote 'set-url' --push origin "ssh://$USER@git.gnome.org/git/network-manager-openswan"
    else
        die "UNEXPECTED"
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
    git fetch origin
    if [[ -n "$LOCAL_MIRROR" ]]; then
        git remote remove local-mirror
    fi
    git commit --allow-empty -m '*** empty initial commit'  # useful, to rebase the following commit
    git add -f -A .
    git commit -m '*** add all'
    ORIG_HEAD="`git rev-parse HEAD`"
    if [[ "x$RELEASE_BASE_COMMIT" == x ]]; then
        # if RELEASE_BASE_COMMIT is not set, try detecting the BASE_COMMIT...

        if [[ "$BUILD_NETWORMANAGER" != "" ]]; then
            # try to find the commit from which the original tarball originates
            # and base the new branch on to of it.
            RELEASE_BASE_COMMIT="$(sed -n 's/^NM_GIT_SHA=\(.*\)/\1/p' configure 2>/dev/null)"
        elif [[ "$BUILD_NETWORMANAGER_OPENVPN" != "" ]]; then
            DATE="$(sed -n 's/%global snapshot .git\(20[0-3][0-9]\)\([0-1][0-9]\)\([0-3][0-9]\)/\1-\2-\3/p' "../$SPEC")"
            if [[ "x$DATE" != x ]]; then
                RELEASE_BASE_COMMIT="$(git rev-list -n1 --date-order --before="$DATE" origin/master 2>/dev/null)"
            fi
        fi
        if [[ "x$RELEASE_BASE_COMMIT" == x ]]; then
            KNOWN_BASE_COMMITS="$(cat <<EOF
# NetworkManager
08670c9163a5d0f15c57c7891ef899eb125d9423  7251704430cb206f2c29bfebc45bd0fb *NetworkManager-0.9.9.0.git20131003.tar.bz2

# libnl3
1a510c57e905c4beb06122b9688162c82d9b044f  d1111959652bd6ad87b2071f61c8c20c *libnl-doc-3.2.24.tar.gz
c4d846f239036c05f516c1c71789e980b64b1e70  2e1c889494d274aca24ce5f6a748e66e *libnl-3.2.22.tar.gz

# NetworkManager-libreswan, NetworkManager-openswan
64c90fd50e57854a3fff3784b92814ffa8159b05  6a373868f85ac3b7c953f7fd6c76e637 *NetworkManager-openswan-0.9.8.0.tar.xz
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
            RELEASE_BASE_COMMIT="$(git rev-parse --verify -q "$RELEASE_BASE_COMMIT" 2>/dev/null)" || die "error detecting RELEASE_BASE_COMMIT=$RELEASE_BASE_COMMIT"
        fi
    fi
    if [[ x != "x$RELEASE_BASE_COMMIT" ]]; then
        git checkout -B master "$RELEASE_BASE_COMMIT" || die "could not checkout master"
        git rm --cached -r :/
        git checkout "$ORIG_HEAD" -- :/
        git clean -fdx :/
        git commit -m '*** add all'
        [[ x == "x$(git diff HEAD "$ORIG_HEAD")" ]] || die "error recreating initial tarball"
    fi
    (
        cat ../makerepo.gitignore 2>/dev/null;
        sed -n 's/^%patch\([0-9]\+\) \+.*-b \+\([^ ]\+\).*$/*\2/p' ../"$SPEC";
        echo '*.[0-9][0-9][0-9][0-9][-.]*.orig'
    ) | LANG=C sort | LANG=C uniq > .gitignore

    git rm --cached -r .
    git add --all .
    git commit -m "*** clean state (ignored files removed)"

    if [[ "$REVERT_COUNT" == "" || $REVERT_COUNT -gt 0 ]]; then

        # parse the list of patches
        IFS=$'\n' read -rd '' -a PATCH_LIST <<<"$(sed -n 's/^Patch\([0-9]\+\): \+\(.*\)$/\1 \2/p' ../"$SPEC" | sort -n)"

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
            patch -f --no-backup-if-mismatch -R -p1 < "../${LAST_PATCH[$i]}" || (
                # error applying patch. Maybe we have a multi line patch...

                split_patch "../${LAST_PATCH[$i]}" ".makerepo-split."

                git reset --hard
                git clean -fdx
                for p in "../${LAST_PATCH[$i]}".makerepo-split.*; do
                    echo ">>> try split part $p for ${LAST_PATCH[$i]}"
                    patch --no-backup-if-mismatch -R -p1 < "$p" || die "error reverting Patch${LAST_PATCH_N[$i]} ${LAST_PATCH[$i]}"
                done
            )
            git add --all .
            git commit --allow-empty -a -m "<< revert Patch${LAST_PATCH_N[$i]} \"${LAST_PATCH[$i]}\"$(get_patch_origin "${LAST_PATCH[$i]}")"
            BASECOMMIT=("`git rev-parse HEAD`" "${BASECOMMIT[@]}")
        done

        # reapply the patches
        for i in ${!PATCH_LIST[@]}; do
            echo "reapply Patch${LAST_PATCH_N[$i]} \"${LAST_PATCH[$i]}\"..."

            # create an empty commit, indicating the commit before starting to reapply
            BASECOMMIT_REVERT="${BASECOMMIT[$((i))]}"
            COMMIT_MSG="$(git log -n1 --format='%s%n%n%b' "$BASECOMMIT_REVERT" | sed '1s/<< revert \(Patch.*"\)$/-- before reapplying \1/')"
            git commit --allow-empty -m "$COMMIT_MSG"

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
        done
    fi
    git checkout "$ORIG_HEAD" -- .
    git checkout HEAD~ -- .gitignore
    git reset

    git gc
popd

if [[ $LOCAL != 0 ]]; then
    rm -rf ./.makerepo.git/
    mv "$DIRNAME/.git" ./.makerepo.git/
    $FEDPKG local
    mv ./.makerepo.git/ "$DIRNAME/.git"
    pushd "$DIRNAME"
        git checkout -- .gitignore
    popd
fi

echo SUCCESS;
