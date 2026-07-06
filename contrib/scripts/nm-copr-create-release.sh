#!/bin/bash

# Create the copr projects for a NetworkManager stable release in the
# networkmanager copr: the release build "NetworkManager-X.Y" and/or the debug
# build "NetworkManager-X.Y-debug". Each new project mirrors the newest existing
# project of the same kind (chroots + per-chroot buildroot config) and wires up
# the custom build (contrib/scripts/nm-copr-build.sh) for the "nm-X-Y" branch.
#
# Usage:
#   contrib/scripts/nm-copr-create-release.sh 1.58                # both + build
#   contrib/scripts/nm-copr-create-release.sh 1.58 --debug-only
#   contrib/scripts/nm-copr-create-release.sh 1.58 --release-only
#   contrib/scripts/nm-copr-create-release.sh 1.58 -n             # dry run
#
# Needs a configured copr-cli token (~/.config/copr).

set -euo pipefail

OWNER=networkmanager
API=https://copr.fedorainfracloud.org/api_3
GL_HOST=gitlab.freedesktop.org
GL_PROJECT=NetworkManager%2FNetworkManager

VERSION=
DRY=
DO_DEBUG=1
DO_RELEASE=1

for a in "$@"; do
    case "$a" in
    -n | --dry-run) DRY=1 ;;
    --debug-only) DO_RELEASE= ;;
    --release-only) DO_DEBUG= ;;
    [0-9]*.[0-9]*) VERSION=$a ;;
    *)
        echo "unknown argument: $a" >&2
        exit 1
        ;;
    esac
done

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+$ ]] ||
    {
        echo "usage: $0 X.Y [--debug-only|--release-only] [-n]   (e.g. $0 1.58)" >&2
        exit 1
    }

GIT_REF="nm-${VERSION//./-}"

tmpd=$(mktemp -d)
trap 'rm -rf "$tmpd"' EXIT

run() {
    printf '+ %s\n' "$*" >&2
    [[ -n "$DRY" ]] || "$@"
}

newest_project() {
    local regex=$1
    curl -sf "$API/project/list?ownername=$OWNER" | python3 -c '
import sys, json, re
regex = sys.argv[1]
names = [p["name"] for p in json.load(sys.stdin)["items"] if re.fullmatch(regex, p["name"])]
names.sort(key=lambda s: [int(x) for x in re.findall(r"\d+", s)])
print(names[-1] if names else "")' "$regex"
}

create_project() {
    local variant=$1
    local suffix debugval desc regex project prev script pid url

    if [[ "$variant" == debug ]]; then
        suffix=-debug
        debugval=1
        desc="Automatic rebuild of NetworkManager's git $GIT_REF branch with DEBUG options enabled."
        regex='NetworkManager-\d+\.\d+-debug'
    else
        suffix=
        debugval=0
        desc="Automatic rebuild of NetworkManager's git $GIT_REF branch."
        regex='NetworkManager-\d+\.\d+'
    fi
    project="NetworkManager-${VERSION}${suffix}"

    prev=$(newest_project "$regex")
    [[ -n "$prev" ]] || {
        echo "no existing $variant project to clone chroots from" >&2
        exit 1
    }
    echo "creating $project, cloning chroots from $prev" >&2

    local chroots chroot_args=()
    mapfile -t chroots < <(curl -sf "$API/project?ownername=$OWNER&projectname=$prev" |
        python3 -c 'import sys, json; print("\n".join(json.load(sys.stdin)["chroot_repos"]))')
    [[ ${#chroots[@]} -gt 0 ]] || {
        echo "could not read chroots from $prev" >&2
        exit 1
    }
    local c
    for c in "${chroots[@]}"; do chroot_args+=(--chroot "$c"); done

    script="$tmpd/build-$variant.sh"
    cat >"$script" <<EOF
#!/bin/bash
export GIT_REF=$GIT_REF
export DEBUG=$debugval
export LTO=
curl https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/raw/main/contrib/scripts/nm-copr-build.sh | bash
EOF

    run copr-cli create "$project" \
        "${chroot_args[@]}" \
        --appstream off \
        --follow-fedora-branching on \
        --description "$desc"

    run copr-cli add-package-custom "$project" \
        --name NetworkManager \
        --script "$script" \
        --script-chroot fedora-latest-x86_64 \
        --script-builddeps 'git-core curl-minimal pam'

    local ch cfg
    for ch in "${chroots[@]}"; do
        mapfile -t cfg < <(copr-cli get-chroot "$OWNER/$prev/$ch" 2>/dev/null | python3 -c '
import sys, json
d = json.load(sys.stdin)
print(" ".join(d.get("additional_repos") or []))
print(" ".join(d.get("additional_packages") or []))')
        [[ -n "${cfg[0]:-}${cfg[1]:-}" ]] || continue
        run copr-cli edit-chroot "$OWNER/$project/$ch" \
            --repos "${cfg[0]}" --packages "${cfg[1]}"
    done

    run copr-cli build-package "$project" --name NetworkManager

    echo >&2
    echo "Project: https://copr.fedorainfracloud.org/coprs/$OWNER/$project/" >&2

    if [[ "$variant" == debug ]]; then
        echo "No push webhook; trigger rebuilds manually:" >&2
        echo "  copr-cli build-package $OWNER/$project --name NetworkManager" >&2
        return
    fi

    pid=$(curl -sf "$API/project?ownername=$OWNER&projectname=$project" |
        python3 -c 'import sys, json; print(json.load(sys.stdin)["id"])' 2>/dev/null || true)
    url="https://copr.fedorainfracloud.org/webhooks/gitlab/${pid:-<PROJECT_ID>}/${COPR_WEBHOOK_SECRET:-<SECRET>}/"

    if [[ -n "${COPR_WEBHOOK_SECRET:-}" ]] && command -v glab >/dev/null; then
        run glab api --hostname "$GL_HOST" "projects/$GL_PROJECT/hooks" -X POST \
            -f "url=$url" -f push_events=true -f "push_events_branch_filter=$GIT_REF"
    else
        cat >&2 <<EOF
Add the push webhook so pushes to $GIT_REF rebuild the project. Copy the secret
from the copr Settings/Integrations page, then run (or set COPR_WEBHOOK_SECRET
and re-run this script):
  glab api --hostname $GL_HOST "projects/$GL_PROJECT/hooks" -X POST \\
    -f "url=$url" -f push_events=true -f "push_events_branch_filter=$GIT_REF"
EOF
    fi
}

[[ -n "$DO_RELEASE" ]] && create_project release
[[ -n "$DO_DEBUG" ]] && create_project debug
