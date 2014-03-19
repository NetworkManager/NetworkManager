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
else
    die "Could not detect dist-git type"
fi

pushd "$DIRNAME"
    git init .
    # if you have a local clone of upstream, symlink it as ../.git/local.
    LOCAL_GIT="$(realpath ../.git/local/)"
    if [[ -d "$LOCAL_GIT/" ]]; then
        git remote add local "$LOCAL_GIT/"
        git fetch local
    fi
    if [[ "$BUILD_NETWORMANAGER" != "" ]]; then
        git remote add origin "git://anongit.freedesktop.org/NetworkManager/NetworkManager"
        git remote 'set-url' --push origin "ssh://$USER@git.freedesktop.org/git/NetworkManager/NetworkManager"
        git config --local notes.displayRef refs/notes/bugs
        git config --local --add remote.origin.fetch refs/tags/*:refs/tags/*
        git config --local --add remote.origin.fetch refs/notes/bugs:refs/notes/bugs
    elif [[ "$BUILD_LIBNL3" != "" ]]; then
        git remote add origin "git://github.com/thom311/libnl.git"
        git remote 'set-url' --push origin "git@github.com:thom311/libnl.git"
    else
        die "UNEXPECTED"
    fi
    git fetch origin
    git commit --allow-empty -m '*** empty initial commit'  # useful, to rebase the following commit
    git add -f -A .
    git commit -m '*** add all'
    cat ../makerepo.gitignore > .gitignore
    git rm --cached -r .
    git add .
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
            git add .
            git commit --allow-empty -a -m "<< revert Patch${LAST_PATCH_N[$i]} \"${LAST_PATCH[$i]}\""
            BASECOMMIT=("`git rev-parse HEAD`" "${BASECOMMIT[@]}")
        done

        # reapply the patches
        for i in ${!PATCH_LIST[@]}; do
            echo "reapply Patch${LAST_PATCH_N[$i]} \"${LAST_PATCH[$i]}\"..."

            # create an empty commit, indicating the commit before starting to reapply
            BASECOMMIT_REVERT="${BASECOMMIT[$((i))]}"
            COMMIT_MSG="$(git log -n1 --format='%s' "$BASECOMMIT_REVERT" | sed 's/<< revert \(Patch.*"\)$/-- before reapplying \1/')"
            git commit --allow-empty -m "$COMMIT_MSG"

            # first try git-am to preserve the commit message, otherwise just revert the last commit
            if git am "../${LAST_PATCH[$i]}"; then
                # The tree to the version before should be identical after reapplying the patch.
                # Just to be sure, reset the commit.
                git reset "${BASECOMMIT[$((i+1))]}" -- .
                COMMIT_MSG="$(git log -n1 --format='%s' "$BASECOMMIT_REVERT" | sed 's/<< revert \(Patch.*"\)$/-- after reapplying \1\n\ngit-am did not fully restore the previous state/')"
                git commit -m "$COMMIT_MSG" || echo "NOTHING TO COMMIT"
            else
                git am --abort
                git reset "${BASECOMMIT[$((i+1))]}" -- .
                COMMIT_MSG="$(git log -n1 --format='%s' "$BASECOMMIT_REVERT" | sed 's/<< revert \(Patch.*"\)$/>> reapply \1/')"
                git commit --allow-empty -m "$COMMIT_MSG"
            fi
            git reset --hard HEAD
        done
    fi
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

