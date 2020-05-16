#!/bin/bash

# Script for searching the git history of keyfile code
# in order to find contributors and copyright holders.

# Base commit. Since this commit are all contributions already
# LGPL-2.1+ licensed. See RELICENSE.md.
H0=a3e75f329446a93a61ca4c458a7657bd919f4fe6

show_related_keyfile_files_origin() {
    # print all related filenames to the keyfile plugin.
    for F in \
          libnm-core/nm-keyfile-internal.h \
          libnm-core/nm-keyfile-utils.c \
          libnm-core/nm-keyfile-utils.h \
          libnm-core/nm-keyfile.c \
          libnm-core/nm-keyfile-reader.c \
          libnm-core/nm-keyfile-writer.c \
          ; do
        git log --pretty='' --name-only --full-history --follow $H0 -- $F \
          | uniq;
        echo;
    done

    git log --pretty='' --name-only $H0 -- system-settings/plugins/keyfile | sort -u | grep -v /tests/ | grep '\.[hc]$'
    echo
    git log --pretty='' --name-only $H0 -- src/settings/plugins/keyfile | sort -u | grep -v /tests/ | grep '\.[hc]$'
}

show_related_keyfile_files_blacklist() {
    # show_related_keyfile_files_origin() prints some files that
    # are unrelated. Blacklist them.
    cat \
    | grep -v info-daemon/NetworkManagerInfoNetworksDialog.h \
    | grep -v nfo-daemon/NetworkManagerInfoPassphraseDialog.h \
    | grep -v src/nm-dbus-nm.h \
    | grep -v src/nm-logging.h \
    | grep -v src/NetworkManagerWireless.h \
    ;
}

show_related_keyfile_files() {
    # print the files names in the git history that are related
    # to keyfile code.
    show_related_keyfile_files_origin \
       | sort -u \
       | grep -v '^$' \
       | show_related_keyfile_files_blacklist
}

commit_has_file() {
    git ls-tree -r "$1" | grep -q "\\s$2"\$
}

print_commit_authors() {
    git --no-pager log --full-history --follow --no-merges --pretty='format:<%ae>' $H0 -- "$1" | sort -u
}

print_blame_authors() {
    local LAST_H

    if commit_has_file $H0 "$1"; then
        LAST_H=$H0
    else
        LAST_H="$(git log --full-history --no-merges -n1 --pretty='format:%H' $H0 -- "$1")"^1
    fi
    git blame --no-progress -C -C -C20 -M -M10 -e "$LAST_H" -- "$1" | sed 's/.*\(<[^>]\+@[^>]\+>\).*/\1/' | sort -u
}

print_grep() {
    git --no-pager log -p --full-history --follow $H0 -- "$1" | grep -i '[a-z0-9]@\|author\|copyright' | sort -u
}

prefix() {
    sed "s/^/>>>$1 /"
}

collect_all() {
    for F; do
       print_commit_authors "$F" | prefix 1
       echo
       print_blame_authors "$F" | prefix 2
       echo
       print_grep "$F" | prefix 3
    done |
    sort |
    uniq |
    sed 's/@/(at)/'
}


F=( $(show_related_keyfile_files) )
for f in "${F[@]}"; do
    echo ">>>>>> file $f"
done
echo
collect_all "${F[@]}"
