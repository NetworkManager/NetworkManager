#!/bin/sh
#
# mockbuild.sh
#
# Generate SRPM from git tree and rebuild it using mock.

SCRIPTDIR="$(dirname "$(readlink -f "$0")")"
FEDORAVER=$(sed -E 's/.*([0-9]{2}).*/\1/g' /etc/fedora-release)
ARCH=$(uname -m)
SRPM=${SCRIPTDIR}/latest/SRPMS/NetworkManager*.src.rpm

alias mock="mock -r fedora-${FEDORAVER}-${ARCH}"

# Generate SRPM
${SCRIPTDIR}/build_clean.sh --srpm --git

# Rebuild SRPM
mock --rebuild ${SRPM}

exit
