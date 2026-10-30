#!/usr/bin/env bash
# Creates (or updates) the GitHub Release for $TAG with notes from
# docs/releases/<base version>.md, the image digest and verification steps,
# and attaches the release assets:
#   open-mcp-portal-<tag>-<os>-<arch>.sbom.spdx.json  the image's SPDX SBOM per
#                                                     platform (BuildKit attestations)
#   open-mcp-portal-<tag>.digest.txt                  the image reference by digest
#   omp-<tag>-<os>-<arch>[.exe]                       the omp command line (cmd/omp), cross-compiled
#                                                     for linux, darwin and windows on amd64 and arm64
#   omp-<tag>-<os>-<arch>[.exe].sigstore.json         its cosign bundle (keyless, like the image)
#   checksums.txt                                     SHA-256 of the files above
# Run by the `release` job in .github/workflows/image.yml (needs GH_TOKEN, TAG,
# DIGEST and read access to the image). Tags with a hyphen (v0.1.0-rc.1)
# become pre-releases and use the base version's notes. A missing notes file,
# SBOM or upload stops the script with a message saying what went wrong.
# The omp binaries are built here (go, CGO_ENABLED=0, -trimpath, the tag's
# version and commit stamped in) and signed with `cosign sign-blob` (needs the
# workflow's id-token permission). RELEASE_CLI_TARGETS (default: all six
# "os/arch" pairs) limits what is built.
# RELEASE_DRY_RUN=1 writes the assets and notes to RELEASE_OUT (default: a
# temporary directory) and skips every GitHub call (gh is not needed). It still
# reads the SBOM attestations from the registry, so DIGEST must be a published
# multi-arch image. To dry-run without one, RELEASE_SBOM_FILE (dry run only)
# names a file holding the output of
#   docker buildx imagetools inspect <image>@<digest> --format '{{ json .SBOM }}'
# and the registry is not contacted. Only the SBOM source differs: tag and
# digest checks, notes, assets and checksums are the real code path. A dry run
# builds the omp binaries but does not sign them, unless RELEASE_COSIGN names a
# cosign command (a stub, in the script's test) to sign with.
set -euo pipefail

fail() {
  echo "::error::github-release: $*" >&2
  exit 1
}

: "${TAG:?TAG is not set}" "${DIGEST:?DIGEST is not set}"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || fail "TAG is not a vX.Y.Z tag: '${TAG}'"
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "DIGEST is not a sha256 digest: '${DIGEST}'"
dry_run="${RELEASE_DRY_RUN:-0}"
tools=(jq sha256sum go)
[ -n "${RELEASE_SBOM_FILE:-}" ] || tools+=(docker)
[ "$dry_run" = 1 ] || tools+=(gh)
cosign_cmd="${RELEASE_COSIGN:-cosign}"
sign_cli=1
if [ "$dry_run" = 1 ] && [ -z "${RELEASE_COSIGN:-}" ]; then sign_cli=0; fi
[ "$sign_cli" = 0 ] || tools+=("$cosign_cmd")
for cmd in "${tools[@]}"; do
  command -v "$cmd" >/dev/null || fail "${cmd} is not installed"
done

repo_slug=ncecere/open-mcp-portal
image="ghcr.io/${repo_slug}"
ref="${image}@${DIGEST}"
base="${TAG%%-*}" # v0.1.0-rc.1 -> v0.1.0
notes_src="docs/releases/${base}.md"
[ -f "$notes_src" ] || fail "no release notes: ${notes_src}"
if [ "$dry_run" = 1 ]; then
  work="${RELEASE_OUT:-$(mktemp -d)}"
  mkdir -p "$work"
else
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
fi
assets="${work}/assets"
mkdir -p "$assets"

# ---- assets ------------------------------------------------------------------

# For a multi-platform index, .SBOM maps each platform ("linux/amd64") to its
# attestations; a single-platform image has .SPDX at the top.
sboms="${work}/sboms.json"
if [ -n "${RELEASE_SBOM_FILE:-}" ]; then
  [ "$dry_run" = 1 ] || fail "RELEASE_SBOM_FILE is only for RELEASE_DRY_RUN=1"
  cp "$RELEASE_SBOM_FILE" "$sboms" || fail "could not read RELEASE_SBOM_FILE ${RELEASE_SBOM_FILE}"
else
  docker buildx imagetools inspect "$ref" --format '{{ json .SBOM }}' >"$sboms" ||
    fail "could not read the SBOM attestations of ${ref}"
fi
if jq -e 'type == "object" and has("SPDX")' "$sboms" >/dev/null; then
  jq '{"image": .}' "$sboms" >"${sboms}.tmp" && mv "${sboms}.tmp" "$sboms"
fi
platforms="$(jq -r 'if type == "object" then keys[] else empty end' "$sboms")"
[ -n "$platforms" ] || fail "${ref} has no SBOM attestation (was it built with an SBOM attestation?)"
files=()
while IFS= read -r platform; do
  name="open-mcp-portal-${TAG}-${platform//\//-}.sbom.spdx.json" # linux/amd64 -> linux-amd64
  [ "$platform" = image ] && name="open-mcp-portal-${TAG}.sbom.spdx.json"
  jq --arg p "$platform" '.[$p].SPDX' "$sboms" >"${assets}/${name}"
  jq -e '.spdxVersion | type == "string" and startswith("SPDX-")' "${assets}/${name}" >/dev/null ||
    fail "the SBOM for ${platform} is not an SPDX document"
  files+=("$name")
done <<<"$platforms"

echo "$ref" >"${assets}/open-mcp-portal-${TAG}.digest.txt"
files+=("open-mcp-portal-${TAG}.digest.txt")

# The omp command line: one static binary per platform, built from this
# checkout, with the tag's version and commit (`omp version`).
module=github.com/ncecere/open-mcp-portal
cli_version="${TAG#v}"
cli_commit="${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
cli_commit="${cli_commit:0:12}"
cli_targets="${RELEASE_CLI_TARGETS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64}"
cli_files=()
host_os="$(go env GOHOSTOS)"
host_arch="$(go env GOHOSTARCH)"
for target in $cli_targets; do
  goos="${target%/*}"
  goarch="${target#*/}"
  [[ "$goos" =~ ^(linux|darwin|windows)$ && "$goarch" =~ ^(amd64|arm64)$ ]] || fail "RELEASE_CLI_TARGETS has an unsupported target '${target}'"
  name="omp-${TAG}-${goos}-${goarch}"
  [ "$goos" = windows ] && name="${name}.exe"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath \
    -ldflags "-s -w -X ${module}/internal/buildinfo.Version=${cli_version} -X ${module}/internal/buildinfo.Commit=${cli_commit}" \
    -o "${assets}/${name}" ./cmd/omp || fail "could not build ${name}"
  if [ "$goos" = "$host_os" ] && [ "$goarch" = "$host_arch" ]; then
    got="$("${assets}/${name}" version)" || fail "${name} does not run"
    [ "$got" = "omp ${cli_version} (${cli_commit})" ] || fail "${name} reports '${got}', not 'omp ${cli_version} (${cli_commit})'"
  fi
  cli_files+=("$name")
done
if [ "${#cli_files[@]}" -gt 0 ] && [ "$sign_cli" = 1 ]; then
  for name in "${cli_files[@]}"; do
    "$cosign_cmd" sign-blob --yes --bundle "${assets}/${name}.sigstore.json" "${assets}/${name}" >/dev/null ||
      fail "could not sign ${name}"
    [ -s "${assets}/${name}.sigstore.json" ] || fail "cosign wrote no bundle for ${name}"
    cli_files+=("${name}.sigstore.json")
  done
fi
files+=("${cli_files[@]}")
(cd "$assets" && sha256sum -- "${files[@]}" >checksums.txt)
files+=(checksums.txt)

# ---- notes -------------------------------------------------------------------

notes="${work}/notes.md"
{
  if [ "$TAG" != "$base" ]; then
    echo "> **Release candidate** for ${base}. Test it before relying on it; the final release follows."
    echo
  fi
  echo "## Image"
  echo
  echo '```'
  echo "${image}:${TAG}"
  echo "$ref"
  echo '```'
  echo
  echo "Deploy by digest. Verify the signature with cosign v3 or newer (keyless, GitHub Actions OIDC):"
  echo
  echo '```sh'
  echo "cosign verify ${ref} \\"
  echo "  --certificate-identity https://github.com/${repo_slug}/.github/workflows/image.yml@refs/tags/${TAG} \\"
  echo "  --certificate-oidc-issuer https://token.actions.githubusercontent.com"
  echo '```'
  echo
  echo "## Release assets"
  echo
  echo "- \`open-mcp-portal-${TAG}-<os>-<arch>.sbom.spdx.json\`: the image's SBOM (SPDX JSON) for each platform, as attached to the image."
  echo "- \`open-mcp-portal-${TAG}.digest.txt\`: the image reference by digest."
  echo "- \`omp-${TAG}-<os>-<arch>\` (\`.exe\` on Windows): the [omp command line](https://github.com/${repo_slug}/blob/${TAG}/docs/cli.md) for linux, darwin and windows on amd64 and arm64, with its cosign bundle \`.sigstore.json\`."
  echo "- \`checksums.txt\`: SHA-256 of the files above (\`sha256sum -c checksums.txt\`)."
  echo
  echo "The SBOM and build provenance are also attached to the image as attestations:"
  echo "\`docker buildx imagetools inspect ${ref} --format '{{ json .SBOM }}'\`."
  echo
  echo "## omp command line"
  echo
  echo "Verify a binary with cosign v3 or newer (the same workflow identity as the image), then check its checksum:"
  echo
  echo '```sh'
  echo "cosign verify-blob omp-${TAG}-linux-amd64 \\"
  echo "  --bundle omp-${TAG}-linux-amd64.sigstore.json \\"
  echo "  --certificate-identity https://github.com/${repo_slug}/.github/workflows/image.yml@refs/tags/${TAG} \\"
  echo "  --certificate-oidc-issuer https://token.actions.githubusercontent.com"
  echo "sha256sum --ignore-missing -c checksums.txt"
  echo '```'
  echo
  echo "Or run it as a container: \`docker build --target omp .\` (docs/cli.md)."
  echo
  # Relative links in docs/releases/ would break on the release page: point
  # them at the files as of this tag.
  blob="https://github.com/${repo_slug}/blob/${TAG}"
  sed -E \
    -e "s#\]\(\.\./\.\./#](${blob}/#g" \
    -e "s#\]\(\.\./#](${blob}/docs/#g" \
    -e "s#\]\((v[0-9]+\.[0-9]+\.[0-9]+\.md)#](${blob}/docs/releases/\1#g" \
    "$notes_src"
} >"$notes"

if [ "$dry_run" = 1 ]; then
  echo "dry run: notes ${notes}, assets in ${assets}"
  ls -l "$assets"
  exit 0
fi

# ---- release -----------------------------------------------------------------

# Name the repository: the asset upload runs from the assets directory, where
# gh can't infer it from a git checkout.
repo="${GITHUB_REPOSITORY:-$repo_slug}"
title="Open MCP Portal ${TAG}"
if gh release view "$TAG" --repo "$repo" >/dev/null 2>&1; then
  gh release edit "$TAG" --repo "$repo" --title "$title" --notes-file "$notes" || fail "could not update the release ${TAG}"
else
  flags=(--repo "$repo" --title "$title" --notes-file "$notes" --verify-tag)
  [ "$TAG" != "$base" ] && flags+=(--prerelease)
  gh release create "$TAG" "${flags[@]}" || fail "could not create the release ${TAG}"
fi
(cd "$assets" && gh release upload "$TAG" --repo "$repo" --clobber "${files[@]}") || fail "could not upload the release assets"
echo "release ${TAG}: ${ref}"
ls -l "$assets"
