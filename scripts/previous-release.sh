#!/usr/bin/env bash
# Names the release the upgrade test installs first, and the digest of its
# image, so the test can install it by digest the way docs/deploy.md tells
# operators to.
#
#   scripts/previous-release.sh               # v0.8.0 ghcr.io/ncecere/open-mcp-portal@sha256:...
#   scripts/previous-release.sh --tag-only    # v0.8.0
#   scripts/previous-release.sh --tag v0.7.0  # that release's digest (older start for a real schema change)
#
# "Previous release" is the newest final release tag (vX.Y.Z, no pre-release
# suffix) that is reachable from HEAD and does not point at HEAD itself: on a
# release tag it is the release before that one, on main the latest release.
# The digest is read from the registry (the image index's Docker-Content-Digest,
# anonymous pull token). When the example overlay at HEAD pins that same tag
# with a digest, the two must agree, so a moved or re-pushed tag fails here
# instead of testing the wrong image.
#
# Needs git, curl and jq. Settings (environment, mostly for tests):
#   OMP_IMAGE_REPO     ncecere/open-mcp-portal
#   OMP_REGISTRY_URL   https://ghcr.io  (the registry API base)
#   OMP_TOKEN_URL      the token endpoint (default <registry>/token)
set -euo pipefail

REPO="${OMP_IMAGE_REPO:-ncecere/open-mcp-portal}"
REGISTRY_URL="${OMP_REGISTRY_URL:-https://ghcr.io}"
REGISTRY_HOST="${REGISTRY_URL#*://}"
TOKEN_URL="${OMP_TOKEN_URL:-${REGISTRY_URL}/token}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() { echo "previous-release: $*" >&2; exit 1; }

# previous_tag: reads tags on stdin, one per line, and the tags on HEAD in the
# environment variable HEAD_TAGS (space separated); prints the newest final
# release tag that is not one of those.
previous_tag() {
  grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V -r | while read -r t; do
    case " ${HEAD_TAGS:-} " in *" $t "*) continue ;; esac
    echo "$t"
    break
  done
}

# registry_digest TAG: the digest of the tag's manifest (index) on the registry.
registry_digest() {
  local tag=$1 token digest
  token="$(curl -fsS --retry 3 --retry-delay 2 --max-time 30 "${TOKEN_URL}?service=${REGISTRY_HOST}&scope=repository:${REPO}:pull" | jq -er .token)" ||
    die "could not get a pull token from ${TOKEN_URL}"
  digest="$(curl -fsSI --retry 3 --retry-delay 2 --max-time 30 -H "Authorization: Bearer ${token}" \
    -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
    "${REGISTRY_URL}/v2/${REPO}/manifests/${tag}" | tr -d '\r' | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: *//p' | head -n 1)" ||
    die "could not read the manifest of ${REPO}:${tag}"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "the registry returned no usable digest for ${REPO}:${tag} (got '${digest}')"
  echo "$digest"
}

# pinned_digest TAG: the digest the example overlay at HEAD pins for TAG, if any.
pinned_digest() {
  local tag=$1 f="${ROOT}/deploy/kubernetes/overlays/example/kustomization.yaml"
  [ -f "$f" ] || return 0
  awk -v tag="$tag" '
    $1 == "newTag:" { seen = ($2 == tag) }
    seen && $1 == "digest:" { print $2; exit }' "$f"
}

tag=""
tag_only=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --tag-only) tag_only=1 ;;
    --tag)
      shift
      [ "$#" -gt 0 ] || die "--tag needs a value"
      tag="$1"
      ;;
    *) die "usage: $0 [--tag-only] [--tag vX.Y.Z]" ;;
  esac
  shift
done

if [ -z "$tag" ]; then
  HEAD_TAGS="$(git -C "$ROOT" tag --points-at HEAD | tr '\n' ' ')"
  export HEAD_TAGS
  tag="$(git -C "$ROOT" tag --merged HEAD --list 'v*' | previous_tag || true)"
  [ -n "$tag" ] || die "no release tag (vX.Y.Z) is reachable from HEAD; fetch tags (git fetch --tags, and a full clone in CI)"
fi
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "'$tag' is not a release tag vX.Y.Z"
if [ "$tag_only" = 1 ]; then
  echo "$tag"
  exit 0
fi

digest="$(registry_digest "$tag")"
pinned="$(pinned_digest "$tag")"
if [ -n "$pinned" ] && [ "$pinned" != "$digest" ]; then
  die "${REPO}:${tag} is ${digest} on the registry but ${pinned} in deploy/kubernetes/overlays/example/kustomization.yaml: the tag moved, or the pin is wrong"
fi
echo "${tag} ${REGISTRY_HOST}/${REPO}@${digest}"
