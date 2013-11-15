#!/bin/bash

set -vx

die() {
    echo "$*" >&2
    exit 1
}

# copy output also to logfile
LOG() {
    echo "$*"
}

abs_path() {
    local F="$1"
    local ALT="$2"

    if [[ "$F" != "" ]]; then
        (cd "$ORIGDIR" && readlink -f "$F") || die "Could not change into $ORIGDIR"
    else
        echo "$2"
    fi
}

get_version() {
    local major minor micro nano
    local F="${1:-"$GITDIR/configure.ac"}"

    vars="$(sed -n 's/^m4_define(\[nm_\(major\|minor\|micro\|nano\)_version\], *\[\([0-9]\+\)\]) *$/local \1='\''\2'\''/p' "$F" 2>/dev/null)"
    eval "$vars"

    [[ -n "$major" && -n "$minor" && "$micro" && "$nano" ]] || return 1
    echo "$major.$minor.$micro.$nano"
}


setup_nmtui() {
    NMTUI="$(abs_path "$NMTUI" "")"
    if [[ "$NMTUI" == "" ]]; then
        NMTUI="$(ls -1 "$GITDIR"/nmtui-*.tar* 2>/dev/null | sort | head -n1)"
    fi
    if [[ "$NMTUI" != "" ]]; then
        if [[ "$NMTUI_VERSION" == "" ]]; then
            NMTUI_VERSION="$(basename "$NMTUI" | sed -n 's/^nmtui-\([0-9]\+\.[0-9]\+\.[0-9]\+\)\.tar.*$/\1/p')"
            [[ "$NMTUI_VERSION" != "" ]] || die "error detecting nmtui version. Set NMTUI_VERSION?"
        fi
        WITH_NMTUI=1
    else
        echo "Build without nmtui"
        NMTUI_VERSION=0
        WITH_NMTUI=0
    fi
}

ORIGDIR="$(readlink -f "$PWD")"
SCRIPTDIR="$(readlink -f "$(dirname "$0")")"
LOG "Change to directory \"$SCRIPTDIR\""
cd "$SCRIPTDIR" || die "could not change into $SCRIPTDIR"
GITDIR="$(cd "$SCRIPTDIR" && git rev-parse --show-toplevel || die "Could not get GITDIR")"

DATE="$(date '+%Y%m%d-%H%M%S')"

BUILDLOG="$(mktemp ./.build.log.XXXXXXX)"
chmod +r "$BUILDLOG"

exec > >(tee "$BUILDLOG")
exec 2>&1

setup_nmtui

UUID=`uuidgen`
RELEASE_VERSION="${RELEASE_VERSION:-999}"
VERSION="${VERSION:-$(get_version || die "Could not read $VERSION")}"
COMMIT="${COMMIT:-$(git rev-parse --verify HEAD | sed 's/^\(.\{10\}\).*/\1/' || die "Error reading HEAD revision")}"
USERNAME="${USERNAME:-"$(git config user.name) <$(git config user.email)>"}"
SPECFILE="$(abs_path "$SPECFILE" "$SCRIPTDIR/NetworkManager.spec")"
SOURCE="$(abs_path "$SOURCE" "$(ls -1 "$GITDIR/NetworkManager-$VERSION"*.tar* 2>/dev/null | head -n1)")"
SOURCE_NETWORKMANAGER_CONF="$(abs_path "$SOURCE_NETWORKMANAGER_CONF" "$SCRIPTDIR/NetworkManager.conf")"
SOURCE_SERVER_CONF="$(abs_path "$SOURCE_SERVER_CONF" "$SCRIPTDIR/00-server.conf")"
LOG "UUID=$UUID"
LOG "VERSION=$VERSION"
LOG "RELEASE_VERSION=$RELEASE_VERSION"
LOG "COMMIT=$COMMIT"
LOG "USERNAME=$USERNAME"
LOG "SPECFILE=$SPECFILE"
LOG "SOURCE=$SOURCE"
LOG "SOURCE_NETWORKMANAGER_CONF=$SOURCE_NETWORKMANAGER_CONF"
LOG "SOURCE_SERVER_CONF=$SOURCE_SERVER_CONF"
LOG "NMTUI=$NMTUI"
LOG "NMTUI_VERSION=$NMTUI_VERSION"

TEMP="$(mktemp -d "$SCRIPTDIR/NetworkManager.$DATE.XXXXXX")"
TEMPBASE="$(basename "$TEMP")"
echo "BASEDIR=$TEMP"

ln -snf "$TEMPBASE" ./latest0
ln "$BUILDLOG" "$TEMPBASE/build.log"
rm -f "$BUILDLOG"

TEMPSPEC="$TEMP/SPECS/NetworkManager.spec"
mkdir -p "$TEMP/SOURCES/" "$TEMP/SPECS/" || die "error creating SPECS directoy"

cp "$SOURCE" "$TEMP/SOURCES/" || die "Could not copy source $SOURCE to $TEMP/SOURCES"
cp "$SOURCE_NETWORKMANAGER_CONF" "$TEMP/SOURCES/NetworkManager.conf" || die "Could not copy source $SOURCE_NETWORKMANAGER_CONF to $TEMP/SOURCES"
cp "$SOURCE_SERVER_CONF" "$TEMP/SOURCES/00-server.conf" || die "Could not copy source $SOURCE_SERVER_CONF to $TEMP/SOURCES"
if [[ "$NMTUI" != "" ]]; then
    cp "$NMTUI" "$TEMP/SOURCES/" || die "Could not copy source $NMTUI to $TEMP/SOURCES"
fi

if [[ "x$CHANGELOG" == x ]]; then
    cat <<EOF > "$TEMP/SOURCES/CHANGELOG"
* $(LOCALE= date '+%a %b %d %Y') $USERNAME - %{release}
- Test build of NetworkManager ($DATE, $UUID)
$(git log -n20 --date=local --format='- %h %s [%an] (%ci)')
- ...
EOF
else
    echo "$CHANGELOG" 2>/dev/null > "$TEMP/SOURCES/CHANGELOG"
fi

sed -e "s/__VERSION__/$VERSION/g" \
    -e "s/__COMMIT__/$COMMIT/g" \
    -e "s/__SOURCE1__/$(basename "$SOURCE")/g" \
    -e "s/__NMTUI_VERSION__/$NMTUI_VERSION/g" \
    -e "s/__WITH_NMTUI__/$WITH_NMTUI/g" \
    -e "s/__RELEASE_VERSION__/$RELEASE_VERSION/g" \
   "$SPECFILE" |
if [[ "$NMTUI" != "" ]]; then
    sed -e 's/^__SOURCE_NMTUI__\([0-9]\+\)$/Source\1: '"$(basename "$NMTUI")"'/'
else
    sed -e '/^__SOURCE_NMTUI__\([0-9]\+\)$/d'
fi |
sed -e "/^__CHANGELOG__$/ \
        {
            r $TEMPBASE/SOURCES/CHANGELOG
            d
        }" > "$TEMPSPEC" || die "Error reading spec file"

rpmbuild --define "_topdir $TEMP" -ba "$TEMPSPEC" || die "ERROR: rpmbuild FAILED"

ls -la "$TEMP"/RPMS/*/*.rpm "$TEMP"/SRPMS/*.rpm

ln -snf "$TEMPBASE" ./latest

