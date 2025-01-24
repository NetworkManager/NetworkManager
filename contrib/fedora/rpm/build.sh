#!/bin/bash

#set -vx

# Set arguments via environment variables.
# Argument can be omitted and defaults will be detected.
#
#   BUILDTYPE=|SRPM
#   NM_RPMBUILD_ARGS=<additional argus for rpmbuild>
#   RELEASE_VERSION=
#   SNAPSHOT=
#   VERSION=
#   COMMIT_FULL=
#   COMMIT=
#   USERNAME=
#   SPECFILE=
#   SOURCE=<path>
#   SOURCE_FROM_GIT=|1|0
#   SOURCE_NETWORKMANAGER_CONF=
#   SOURCE_CONFIG_SERVER=
#   SOURCE_CONFIG_CONNECTIVITY_FEDORA=
#   SOURCE_CONFIG_CONNECTIVITY_REDHAT=
#   SOURCE_SYSCTL_RP_FILTER_REDHAT=
#   SOURCE_README_IFCFG_FILES=
#   SOURCE_README_IFCFG_MIGRATED=
#   SIGN_SOURCE=
#   DO_RELEASE=
#   BCOND_DEFAULT_DEBUG=
#   BCOND_DEFAULT_LTO=
#   BCOND_DEFAULT_TEST=

die() {
    echo "$*" >&2
    exit 1
}

# copy output also to logfile
LOG() {
    echo "$*"
}

coerce_bool() {
    case "$1" in
        no|n|NO|N|0)
            echo 0
            ;;
        yes|y|YES|Y|1)
            echo 1
            ;;
        "")
            printf '%s' "$2"
            ;;
    esac
}

in_set() {
    local v="$1"
    shift
    for v2; do
        test "$v" = "$v2" && return 0
    done
    return 1
}

abs_path() {
    local F="$1"

    if [[ "$F" != "" ]]; then
        F="$(cd "$ORIGDIR" && readlink -f "$F")" || exit 55
        [[ -f "$F" ]] || exit 55
    else
        F="$2"
    fi
    printf '%s' "$F"
    exit 0
}

get_version() {
    grep -E -m1 '^\s+version:' "$GITDIR/meson.build" | cut -d"'" -f2
}

write_changelog() {
    if [[ "x$CHANGELOG" == x ]]; then
        cat <<- EOF
	* $(LC_TIME=C date '+%a %b %d %Y') $USERNAME - %{epoch_version}:%{version}-%{release_version}%{?snap}
	- build of NetworkManager ($DATE, uuid: $UUID, git: $COMMIT_FULL)
	$(git log -n20 --date=local --format='- %h %s [%an] (%ci)')
	- ...
	EOF
    else
        echo "$CHANGELOG"
    fi > "$TEMP/SOURCES/CHANGELOG"
}

ORIGDIR="$(readlink -f "$PWD")"
SCRIPTDIR="$(dirname "$(readlink -f "$0")")"
LOG "Change to directory \"$SCRIPTDIR\""
cd "$SCRIPTDIR" || die "could not change into $SCRIPTDIR"
GITDIR="$(cd "$SCRIPTDIR" && git rev-parse --show-toplevel || die "Could not get GITDIR")"

DATE="$(date '+%Y%m%d-%H%M%S')"

BUILDLOG="$(mktemp ./.build.log.XXXXXXX)"
chmod +r "$BUILDLOG"

exec > >(tee "$BUILDLOG")
exec 2>&1

UUID=`uuidgen`
RELEASE_VERSION="${RELEASE_VERSION:-$(git rev-list HEAD | wc -l)}"
SNAPSHOT="${SNAPSHOT:-%{nil\}}"
VERSION="${VERSION:-$(get_version || die "Could not read $VERSION")}"
COMMIT_FULL="${COMMIT_FULL:-$(git rev-parse --verify HEAD || die "Error reading HEAD revision")}"
COMMIT="${COMMIT:-$(printf '%s' "$COMMIT_FULL" | sed 's/^\(.\{10\}\).*/\1/' || die "Error reading HEAD revision")}"
BCOND_DEFAULT_DEBUG="${BCOND_DEFAULT_DEBUG:-0}"
BCOND_DEFAULT_TEST="${BCOND_DEFAULT_TEST:-0}"
BCOND_DEFAULT_LTO="${BCOND_DEFAULT_LTO}"
USERNAME="${USERNAME:-"$(git config user.name) <$(git config user.email)>"}"
SPECFILE="$(abs_path "$SPECFILE" "$SCRIPTDIR/NetworkManager.spec")" || die "invalid \$SPECFILE argument"
SOURCE_FROM_GIT="$(coerce_bool "$SOURCE_FROM_GIT" "")"
SOURCE="$(abs_path "$SOURCE")" || die "invalid \$SOURCE argument"
DO_RELEASE="$(coerce_bool "$DO_RELEASE" "0")"
SIGN_SOURCE="$(coerce_bool "$SIGN_SOURCE" "$DO_RELEASE")"
if [ -n "$SOURCE" ]; then
    [[ "$SOURCE_FROM_GIT" == 1 ]] && die "Cannot set both \$SOURCE and \$SOURCE_FROM_GIT=1"
    SOURCE_FROM_GIT=0
elif [[ "$SOURCE_FROM_GIT" != "1" ]]; then
    SOURCE="$(ls -1 "$GITDIR/NetworkManager-${VERSION}.tar."* 2>/dev/null | head -n1)"
    if [[ -z "$SOURCE" ]]; then
        [[ "$SOURCE_FROM_GIT" == "0" ]] && die "Either set \$SOURCE or set \$SOURCE_FROM_GIT=1"
        SOURCE_FROM_GIT=1
    else
        SOURCE_FROM_GIT=0
    fi
fi

SOURCE_NETWORKMANAGER_CONF="$(abs_path "$SOURCE_NETWORKMANAGER_CONF" "$SCRIPTDIR/NetworkManager.conf")" || die "invalid \$SOURCE_NETWORKMANAGER_CONF argument"
SOURCE_CONFIG_SERVER="$(abs_path "$SOURCE_CONFIG_SERVER" "$SCRIPTDIR/00-server.conf")" || die "invalid \$SOURCE_CONFIG_SERVER argument"
SOURCE_CONFIG_CONNECTIVITY_FEDORA="$(abs_path "$SOURCE_CONFIG_CONNECTIVITY_FEDORA" "$SCRIPTDIR/20-connectivity-fedora.conf")" || die "invalid \$SOURCE_CONFIG_CONNECTIVITY_FEDORA argument"
SOURCE_CONFIG_CONNECTIVITY_REDHAT="$(abs_path "$SOURCE_CONFIG_CONNECTIVITY_REDHAT" "$SCRIPTDIR/20-connectivity-redhat.conf")" || die "invalid \$SOURCE_CONFIG_CONNECTIVITY_REDHAT argument"
SOURCE_CONFIG_WIFI_MAC_ADDR="$(abs_path "$SOURCE_CONFIG_WIFI_MAC_ADDR" "$SCRIPTDIR/22-wifi-mac-addr.conf")" || die "invalid \$SOURCE_CONFIG_WIFI_MAC_ADDR argument"
SOURCE_SYSCTL_RP_FILTER_REDHAT="$(abs_path "$SOURCE_SYSCTL_RP_FILTER_REDHAT" "$SCRIPTDIR/70-nm-connectivity.conf")" || die "invalid \$SOURCE_SYSCTL_RP_FILTER_REDHAT argument"
SOURCE_README_IFCFG_FILES="$(abs_path "$SOURCE_README_IFCFG_FILES" "$SCRIPTDIR/readme-ifcfg-rh.txt")" || die "invalid \$SOURCE_README_IFCFG_FILES argument"
SOURCE_README_IFCFG_MIGRATED="$(abs_path "$SOURCE_README_IFCFG_MIGRATED" "$SCRIPTDIR/readme-ifcfg-rh-migrated.txt")" || die "invalid \$SOURCE_README_IFCFG_MIGRATED argument"

TEMP="$(mktemp -d "$SCRIPTDIR/NetworkManager.$DATE.XXXXXX")"
TEMPBASE="$(basename "$TEMP")"

if [[ "$SOURCE_FROM_GIT" == "1" ]]; then
    mkdir -p "$TEMP/SOURCES"
    SOURCE="$TEMP/SOURCES/NetworkManager-${VERSION}.tar.xz"
    (cd "$GITDIR" && git archive --prefix="NetworkManager-$VERSION"/ "$COMMIT_FULL") | xz -1 > "$SOURCE"
fi

LOG "VERSION=$VERSION"
LOG "RELEASE_VERSION=$RELEASE_VERSION"
LOG "SNAPSHOT=$SNAPSHOT"
LOG "COMMIT_FULL=$COMMIT_FULL"
LOG "COMMIT=$COMMIT"
LOG "USERNAME=$USERNAME"
LOG "SPECFILE=$SPECFILE"
LOG "SOURCE=$SOURCE"
LOG "SIGN_SOURCE=$SIGN_SOURCE"
LOG "DO_RELEASE=$DO_RELEASE"
LOG "SOURCE_FROM_GIT=$SOURCE_FROM_GIT"
LOG "SOURCE_NETWORKMANAGER_CONF=$SOURCE_NETWORKMANAGER_CONF"
LOG "SOURCE_CONFIG_SERVER=$SOURCE_CONFIG_SERVER"
LOG "SOURCE_CONFIG_CONNECTIVITY_FEDORA=$SOURCE_CONFIG_CONNECTIVITY_FEDORA"
LOG "SOURCE_CONFIG_CONNECTIVITY_REDHAT=$SOURCE_CONFIG_CONNECTIVITY_REDHAT"
LOG "SOURCE_SYSCTL_RP_FILTER_REDHAT=$SOURCE_SYSCTL_RP_FILTER_REDHAT"
LOG "SOURCE_README_IFCFG_FILES=$SOURCE_README_IFCFG_FILES"
LOG "SOURCE_README_IFCFG_MIGRATED=$SOURCE_README_IFCFG_MIGRATED"
LOG "BUILDTYPE=$BUILDTYPE"
LOG "NM_RPMBUILD_ARGS=$NM_RPMBUILD_ARGS"
LOG "BCOND_DEFAULT_DEBUG=$BCOND_DEFAULT_DEBUG"
LOG "BCOND_DEFAULT_LTO=$BCOND_DEFAULT_LTO"
LOG "BCOND_DEFAULT_TEST=$BCOND_DEFAULT_TEST"
LOG ""
LOG "UUID=$UUID"
LOG "BASEDIR=$TEMP"

in_set "$BCOND_DEFAULT_DEBUG" 0 1 || die "Invalid value for \$BCOND_DEFAULT_DEBUG: \"$BCOND_DEFAULT_DEBUG\""
in_set "$BCOND_DEFAULT_LTO" '' 0 1 || die "Invalid value for \$BCOND_DEFAULT_LTO: \"$BCOND_DEFAULT_LTO\""
in_set "$BCOND_DEFAULT_TEST" 0 1 || die "Invalid value for \$BCOND_DEFAULT_TEST: \"$BCOND_DEFAULT_TEST\""

ln -snf "$TEMPBASE" ./latest0
ln "$BUILDLOG" "$TEMPBASE/build.log"
rm -f "$BUILDLOG"

TEMPSPEC="$TEMP/SPECS/NetworkManager.spec"
mkdir -p "$TEMP/SOURCES/" "$TEMP/SPECS/" || die "error creating SPECS directory"

if [[ "$(dirname "$SOURCE")" != "$TEMP/SOURCES" ]]; then
    cp "$SOURCE" "$TEMP/SOURCES/" || die "Could not copy source $SOURCE to $TEMP/SOURCES"
fi
cp "$SOURCE_NETWORKMANAGER_CONF" "$TEMP/SOURCES/NetworkManager.conf" || die "Could not copy source $SOURCE_NETWORKMANAGER_CONF to $TEMP/SOURCES"
cp "$SOURCE_CONFIG_SERVER" "$TEMP/SOURCES/00-server.conf" || die "Could not copy source $SOURCE_CONFIG_SERVER to $TEMP/SOURCES"
cp "$SOURCE_CONFIG_CONNECTIVITY_FEDORA" "$TEMP/SOURCES/20-connectivity-fedora.conf" || die "Could not copy source $SOURCE_CONFIG_CONNECTIVITY_FEDORA to $TEMP/SOURCES"
cp "$SOURCE_CONFIG_CONNECTIVITY_REDHAT" "$TEMP/SOURCES/20-connectivity-redhat.conf" || die "Could not copy source $SOURCE_CONFIG_CONNECTIVITY_REDHAT to $TEMP/SOURCES"
cp "$SOURCE_CONFIG_WIFI_MAC_ADDR" "$TEMP/SOURCES/22-wifi-mac-addr.conf" || die "Could not copy source $SOURCE_CONFIG_WIFI_MAC_ADDR to $TEMP/SOURCES"
cp "$SOURCE_SYSCTL_RP_FILTER_REDHAT" "$TEMP/SOURCES/70-nm-connectivity.conf" || die "Could not copy source $SOURCE_SYSCTL_RP_FILTER_REDHAT to $TEMP/SOURCES"
cp "$SOURCE_README_IFCFG_FILES" "$TEMP/SOURCES/readme-ifcfg-rh.txt" || die "Could not copy source $SOURCE_README_IFCFG_FILES to $TEMP/SOURCES"
cp "$SOURCE_README_IFCFG_MIGRATED" "$TEMP/SOURCES/readme-ifcfg-rh-migrated.txt" || die "Could not copy source $SOURCE_README_IFCFG_MIGRATED to $TEMP/SOURCES"

write_changelog

sed -e "s/__VERSION__/$VERSION/g" \
    -e "s/__RELEASE_VERSION__/$RELEASE_VERSION/g" \
    -e "s/__SNAPSHOT__/$SNAPSHOT/g" \
    -e "s/__COMMIT__/$COMMIT/g" \
    -e "s/__COMMIT_FULL__/$COMMIT_FULL/g" \
    -e "s/__SNAPSHOT__/$SNAPSHOT/g" \
    -e "s/__SOURCE1__/$(basename "$SOURCE")/g" \
    -e "s/__BCOND_DEFAULT_DEBUG__/$BCOND_DEFAULT_DEBUG/g" \
    -e "s/__BCOND_DEFAULT_LTO__/${BCOND_DEFAULT_LTO:-"%{nil}"}/g" \
    -e "s/__BCOND_DEFAULT_TEST__/$BCOND_DEFAULT_TEST/g" \
   "$SPECFILE" |
sed -e "/^__CHANGELOG__$/ \
        {
            r $TEMPBASE/SOURCES/CHANGELOG
            d
        }" > "$TEMPSPEC" || die "Error reading spec file"

case "$BUILDTYPE" in
    "SRPM")
        RPM_BUILD_OPTION=-bs
        ;;
    *)
        RPM_BUILD_OPTION=-ba
        ;;
esac

rpmbuild --define "_topdir $TEMP" $RPM_BUILD_OPTION "$TEMPSPEC" $NM_RPMBUILD_ARGS || die "ERROR: rpmbuild FAILED"

LS_EXTRA=()

if [ "$SIGN_SOURCE" = 1 ]; then
    SIGNKEY="$(git config --get user.signingkey)"
    if [ "$SIGNKEY" != "" ]; then
        SIGNKEY="--local-user $(printf '%q' "$SIGNKEY")"
    fi
    gpg $SIGNKEY --output "$SOURCE.sig" --armor --detach-sig "$SOURCE" || die "ERROR: failure to sign $SOURCE"
    LS_EXTRA+=("$SOURCE.sig")
fi

ln -snf "$TEMPBASE" ./latest
TEMP_LATEST="$(readlink -f .)"/latest

LOG
LOG
LOG "Finished with success."
LOG
LOG "See \"$TEMP_LATEST/\" which symlinks to \"$TEMPBASE\""
LOG
LOG "Result:"
ls -dla \
    "$TEMP_LATEST" \
    "$SOURCE" \
    "${LS_EXTRA[@]}" \
    "$(dirname "$TEMP_LATEST")/$TEMPBASE/" \
    "$TEMP_LATEST"/RPMS/*/ \
    "$TEMP_LATEST"/RPMS/*/*.rpm \
    "$TEMP_LATEST"/SRPMS/ \
    "$TEMP_LATEST"/SRPMS/*.rpm \
    2>/dev/null | sed 's/^/    /'
LOG
if [[ "$BUILDTYPE" == "SRPM" ]]; then
    LOG sudo $(command -v dnf &>/dev/null && echo dnf builddep || echo yum-builddep) $TEMP_LATEST/SRPMS/*.src.rpm
    LOG
else
    LOG "sudo $(command -v dnf &>/dev/null && echo dnf || echo yum) install '$TEMP_LATEST/RPMS'/*/*.rpm"
    LOG
fi

if [[ "$DO_RELEASE" == 1 ]]; then
    LOG "RELEASE \"$SOURCE\" :"
    for c in md5 sha1 sha256 sha512; do
        LOG "$(printf '%8s: %s' "$c" $("${c}sum" "$SOURCE" | sed 's/ .*//'))"
    done
    LOG
fi
