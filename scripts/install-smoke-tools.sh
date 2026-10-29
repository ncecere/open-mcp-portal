#!/usr/bin/env bash
# Installs the pinned, checksum-verified binaries the Kubernetes scenarios need
# (kind, kubectl, shellcheck, k6) into a directory, Linux amd64 or arm64.
# Every download is compared with a SHA-256 written below before it is made
# executable; a mismatch deletes it and fails. The workflows and a developer
# machine use this one script, so the versions and sums live in one place.
#
#   scripts/install-smoke-tools.sh DEST_DIR kind kubectl shellcheck k6
#
# Prints DEST_DIR on success. The caller puts it first on PATH.
#
# Where the sums come from (all re-checked against the release's own checksum
# file or the GitHub release asset digest when they were pinned):
#   kind v0.33.0        kind-linux-<arch>.sha256sum of the release
#   kubectl v1.37.0     https://dl.k8s.io/release/v1.37.0/bin/linux/<arch>/kubectl.sha256
#   ShellCheck v0.11.0  GitHub release asset digests (the project publishes no checksum file)
#   k6 v2.3.0           k6-v2.3.0-checksums.txt of the release
set -euo pipefail

KIND_VERSION="v0.33.0"
KUBECTL_VERSION="v1.37.0"
SHELLCHECK_VERSION="v0.11.0"
K6_VERSION="v2.3.0"

usage() {
  echo "usage: $0 DEST_DIR kind|kubectl|shellcheck|k6..." >&2
  exit 2
}
[ "$#" -ge 2 ] || usage
DEST="$1"
shift

[ "$(uname -s)" = Linux ] || { echo "install-smoke-tools: Linux only (install the tools by hand elsewhere)" >&2; exit 1; }
case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) echo "install-smoke-tools: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
mkdir -p "$DEST"
DEST="$(cd "$DEST" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/omp-tools.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# fetch URL FILE SHA256: download with retries (a download is the one thing
# worth retrying), then verify.
fetch() {
  local url=$1 file=$2 want=$3 got
  curl -fsSL --retry 3 --retry-delay 2 --max-time 180 -o "$file" "$url"
  got="$(sha256sum "$file" | cut -d' ' -f1)"
  if [ "$got" != "$want" ]; then
    rm -f "$file"
    echo "install-smoke-tools: checksum mismatch for $url: got $got, want $want" >&2
    exit 1
  fi
}

install_kind() {
  local sum
  case "$ARCH" in
    amd64) sum=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d ;;
    arm64) sum=20022bee6cfcd5086cb7234d218e3454e6090022f2a8f55d1fa7fcf42c3867a2 ;;
  esac
  fetch "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-${ARCH}" "$WORK/kind" "$sum"
  install -m 0755 "$WORK/kind" "$DEST/kind"
}

install_kubectl() {
  local sum
  case "$ARCH" in
    amd64) sum=6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f ;;
    arm64) sum=922df28df248cc00a9e025f947704f1d1482de64ece54cfe57e61f19eaf1eef3 ;;
  esac
  fetch "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl" "$WORK/kubectl" "$sum"
  install -m 0755 "$WORK/kubectl" "$DEST/kubectl"
}

install_shellcheck() {
  local sum arch
  case "$ARCH" in
    amd64) arch=x86_64 sum=b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6 ;;
    arm64) arch=aarch64 sum=68a8133197a50beb8803f8d42f9908d1af1c5540d4bb05fdfca8c1fa47decefc ;;
  esac
  fetch "https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/shellcheck-${SHELLCHECK_VERSION}.linux.${arch}.tar.gz" "$WORK/shellcheck.tgz" "$sum"
  tar -xzf "$WORK/shellcheck.tgz" -C "$WORK" "shellcheck-${SHELLCHECK_VERSION}/shellcheck"
  install -m 0755 "$WORK/shellcheck-${SHELLCHECK_VERSION}/shellcheck" "$DEST/shellcheck"
}

install_k6() {
  local sum
  case "$ARCH" in
    amd64) sum=39c3117b6af817592dcd0ce4242105c0a7af10948c2a425306f0be8f7a8a8ab1 ;;
    arm64) sum=5ca3433e8201da72a284aaa241a1bb5fb47f4abb4e384d39410ddd8062f49b90 ;;
  esac
  fetch "https://github.com/grafana/k6/releases/download/${K6_VERSION}/k6-${K6_VERSION}-linux-${ARCH}.tar.gz" "$WORK/k6.tgz" "$sum"
  tar -xzf "$WORK/k6.tgz" -C "$WORK" "k6-${K6_VERSION}-linux-${ARCH}/k6"
  install -m 0755 "$WORK/k6-${K6_VERSION}-linux-${ARCH}/k6" "$DEST/k6"
}

for tool in "$@"; do
  case "$tool" in
    kind | kubectl | shellcheck | k6) "install_${tool}" ;;
    *) usage ;;
  esac
  echo "install-smoke-tools: $tool installed in $DEST" >&2
done
echo "$DEST"
