#!/bin/bash

#set -vx

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
	* $(LC_TIME=C date '+%a %b %d %Y') $USERNAME - %{epoch_version}:%{version}-%{release_version}%{snapshot}%{git_sha_version}
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
VERSION="${VERSION:-$(get_version || die "Could not read $VERSION")}"
COMMIT_FULL="${COMMIT_FULL:-$(git rev-parse --verify HEAD || die "Error reading HEAD revision")}"
COMMIT="${COMMIT:-$(git rev-parse --verify HEAD | sed 's/^\(.\{10\}\).*/\1/' || die "Error reading HEAD revision")}"
USERNAME="${USERNAME:-"$(git config user.name) <$(git config user.email)>"}"
SPECFILE="$(abs_path "$SPECFILE" "$SCRIPTDIR/NetworkManager.spec")"
_SOURCE="$SOURCE"
SOURCE="$(abs_path "$SOURCE" "$(ls -1 "$GITDIR/NetworkManager-$VERSION"*.tar* 2>/dev/null | head -n1)")"
[[ -f "$SOURCE" ]] || die "could not find source ${_SOURCE:-$GITDIR/NetworkManager-$VERSION*.tar*} . Did you execute \`make dist\`? Otherwise set \$SOURCE variable"
SOURCE_NETWORKMANAGER_CONF="$(abs_path "$SOURCE_NETWORKMANAGER_CONF" "$SCRIPTDIR/NetworkManager.conf")"
SOURCE_CONFIG_SERVER="$(abs_path "$SOURCE_CONFIG_SERVER" "$SCRIPTDIR/00-server.conf")"
SOURCE_CONFIG_CONNECTIVITY_FEDORA="$(abs_path "$SOURCE_CONFIG_CONNECTIVITY_FEDORA" "$SCRIPTDIR/20-connectivity-fedora.conf")"

TEMP="$(mktemp -d "$SCRIPTDIR/NetworkManager.$DATE.XXXXXX")"
TEMPBASE="$(basename "$TEMP")"

LOG "UUID=$UUID"
LOG "VERSION=$VERSION"
LOG "RELEASE_VERSION=$RELEASE_VERSION"
LOG "COMMIT=$COMMIT"
LOG "USERNAME=$USERNAME"
LOG "SPECFILE=$SPECFILE"
LOG "SOURCE=$SOURCE"
LOG "SOURCE_NETWORKMANAGER_CONF=$SOURCE_NETWORKMANAGER_CONF"
LOG "SOURCE_CONFIG_SERVER=$SOURCE_CONFIG_SERVER"
LOG "SOURCE_CONFIG_CONNECTIVITY_FEDORA=$SOURCE_CONFIG_CONNECTIVITY_FEDORA"
LOG "BASEDIR=$TEMP"

ln -snf "$TEMPBASE" ./latest0
ln "$BUILDLOG" "$TEMPBASE/build.log"
rm -f "$BUILDLOG"

TEMPSPEC="$TEMP/SPECS/NetworkManager.spec"
mkdir -p "$TEMP/SOURCES/" "$TEMP/SPECS/" || die "error creating SPECS directoy"

cp "$SOURCE" "$TEMP/SOURCES/" || die "Could not copy source $SOURCE to $TEMP/SOURCES"
cp "$SOURCE_NETWORKMANAGER_CONF" "$TEMP/SOURCES/NetworkManager.conf" || die "Could not copy source $SOURCE_NETWORKMANAGER_CONF to $TEMP/SOURCES"
cp "$SOURCE_CONFIG_SERVER" "$TEMP/SOURCES/00-server.conf" || die "Could not copy source $SOURCE_CONFIG_SERVER to $TEMP/SOURCES"
cp "$SOURCE_CONFIG_CONNECTIVITY_FEDORA" "$TEMP/SOURCES/20-connectivity-fedora.conf" || die "Could not copy source $SOURCE_CONFIG_CONNECTIVITY_FEDORA to $TEMP/SOURCES"

write_changelog

sed -e "s/__VERSION__/$VERSION/g" \
    -e "s/__RELEASE_VERSION__/$RELEASE_VERSION/g" \
    -e "s/__COMMIT__/$COMMIT/g" \
    -e "s/__COMMIT_FULL__/$COMMIT_FULL/g" \
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

rpmbuild --define "_topdir $TEMP" $RPM_BUILD_OPTION "$TEMPSPEC" || die "ERROR: rpmbuild FAILED"

ln -snf "$TEMPBASE" ./latest
TEMP_LATEST="$(readlink -f .)"/latest

LOG
LOG
LOG "Finished with success."
LOG
LOG "See \"$TEMP_LATEST/\" which symlinks to \"$TEMPBASE\""
LOG
LOG "Result:"
ls -dla "$TEMP_LATEST" "$(dirname "$TEMP_LATEST")/$TEMPBASE/" "$TEMP_LATEST"/RPMS/*/ "$TEMP_LATEST"/RPMS/*/*.rpm "$TEMP_LATEST"/SRPMS/ "$TEMP_LATEST"/SRPMS/*.rpm 2>/dev/null | sed 's/^/    /'


