#!/bin/bash

#set -vx

# Set arguments via environment variables.
# Argument can be omited and defaults will be detected.
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
    local major minor micro
    local F="${1:-"$GITDIR/configure.ac"}"

    vars="$(sed -n 's/^m4_define(\[nm_\(major\|minor\|micro\)_version\], *\[\([0-9]\+\)\]) *$/local \1='\''\2'\''/p' "$F" 2>/dev/null)"
    eval "$vars"

    [[ -n "$major" && -n "$minor" && "$micro" ]] || return 1
    echo "$major.$minor.$micro"
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
USERNAME="${USERNAME:-"$(git config user.name) <$(git config user.email)>"}"
SPECFILE="$(abs_path "$SPECFILE" "$SCRIPTDIR/NetworkManager.spec")" || die "invalid \$SPECFILE argument"
SOURCE_FROM_GIT="$(coerce_bool "$SOURCE_FROM_GIT" "")"
SOURCE="$(abs_path "$SOURCE")" || die "invalid \$SOURCE argument"
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

TEMP="$(mktemp -d "$SCRIPTDIR/NetworkManager.$DATE.XXXXXX")"
TEMPBASE="$(basename "$TEMP")"

if [[ "$SOURCE_FROM_GIT" == "1" ]]; then
    mkdir -p "$TEMP/SOURCES"
    SOURCE="$TEMP/SOURCES/NetworkManager-${VERSION}.tar.xz"
    (cd "$GITDIR" && git archive --prefix="NetworkManager-$VERSION"/ "$COMMIT_FULL") | xz > "$SOURCE"
fi

LOG "VERSION=$VERSION"
LOG "RELEASE_VERSION=$RELEASE_VERSION"
LOG "SNAPSHOT=$SNAPSHOT"
LOG "COMMIT_FULL=$COMMIT_FULL"
LOG "COMMIT=$COMMIT"
LOG "USERNAME=$USERNAME"
LOG "SPECFILE=$SPECFILE"
LOG "SOURCE=$SOURCE"
LOG "SOURCE_FROM_GIT=$SOURCE_FROM_GIT"
LOG "SOURCE_NETWORKMANAGER_CONF=$SOURCE_NETWORKMANAGER_CONF"
LOG "SOURCE_CONFIG_SERVER=$SOURCE_CONFIG_SERVER"
LOG "SOURCE_CONFIG_CONNECTIVITY_FEDORA=$SOURCE_CONFIG_CONNECTIVITY_FEDORA"
LOG "BUILDTYPE=$BUILDTYPE"
LOG "NM_RPMBUILD_ARGS=$NM_RPMBUILD_ARGS"
LOG ""
LOG "UUID=$UUID"
LOG "BASEDIR=$TEMP"

ln -snf "$TEMPBASE" ./latest0
ln "$BUILDLOG" "$TEMPBASE/build.log"
rm -f "$BUILDLOG"

TEMPSPEC="$TEMP/SPECS/NetworkManager.spec"
mkdir -p "$TEMP/SOURCES/" "$TEMP/SPECS/" || die "error creating SPECS directoy"

if [[ "$(dirname "$SOURCE")" != "$TEMP/SOURCES" ]]; then
    cp "$SOURCE" "$TEMP/SOURCES/" || die "Could not copy source $SOURCE to $TEMP/SOURCES"
fi
cp "$SOURCE_NETWORKMANAGER_CONF" "$TEMP/SOURCES/NetworkManager.conf" || die "Could not copy source $SOURCE_NETWORKMANAGER_CONF to $TEMP/SOURCES"
cp "$SOURCE_CONFIG_SERVER" "$TEMP/SOURCES/00-server.conf" || die "Could not copy source $SOURCE_CONFIG_SERVER to $TEMP/SOURCES"
cp "$SOURCE_CONFIG_CONNECTIVITY_FEDORA" "$TEMP/SOURCES/20-connectivity-fedora.conf" || die "Could not copy source $SOURCE_CONFIG_CONNECTIVITY_FEDORA to $TEMP/SOURCES"

write_changelog

sed -e "s/__VERSION__/$VERSION/g" \
    -e "s/__RELEASE_VERSION__/$RELEASE_VERSION/g" \
    -e "s/__SNAPSHOT__/$SNAPSHOT/g" \
    -e "s/__COMMIT__/$COMMIT/g" \
    -e "s/__COMMIT_FULL__/$COMMIT_FULL/g" \
    -e "s/__SNAPSHOT__/$SNAPSHOT/g" \
    -e "s/__SOURCE1__/$(basename "$SOURCE")/g" \
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
    "$(dirname "$TEMP_LATEST")/$TEMPBASE/" \
    "$TEMP_LATEST"/RPMS/*/ \
    "$TEMP_LATEST"/RPMS/*/*.rpm \
    "$TEMP_LATEST"/SRPMS/ \
    "$TEMP_LATEST"/SRPMS/*.rpm \
    2>/dev/null | sed 's/^/    /'
LOG
if [[ "$BUILDTYPE" == "SRPM" ]]; then
    LOG sudo $(which dnf &>/dev/null && echo dnf builddep || echo yum-builddep) $TEMP_LATEST/SRPMS/*.src.rpm
    LOG
else
    LOG "sudo $(which dnf &>/dev/null && echo dnf || echo yum) install '$TEMP_LATEST/RPMS'/*/*.rpm"
    LOG
fi

