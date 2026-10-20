#!/usr/bin/env bash
# Renders the base and every overlay with kustomize and validates the output
# with kubeconform -strict (Gateway API schemas from the pinned
# datreeio/CRDs-catalog). Also checks that the generated ConfigMap carries a
# content hash that the Deployment references, so configuration changes roll
# the pods.
#
# Used by `make k8s-validate`. Tools are overridable:
#   KUSTOMIZE=kustomize KUBECONFORM=kubeconform deploy/kubernetes/scripts/validate.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
KUSTOMIZE="${KUSTOMIZE:-kustomize}"
KUBECONFORM="${KUBECONFORM:-kubeconform}"
K8S_SCHEMA_VERSION="${K8S_SCHEMA_VERSION:-1.34.0}"
CRDS_CATALOG_REF="${CRDS_CATALOG_REF:-ad3b08c5045129d7bb1eeffd8e61719b2c8dd1e2}"
crd_schemas="https://raw.githubusercontent.com/datreeio/CRDs-catalog/${CRDS_CATALOG_REF}/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"

# kustomize refuses absolute paths outside the kustomization root, so the
# base build happens in a scratch directory next to base/.
scratch="$(mktemp -d "${root}/.tmp.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

validate() { # name, rendered file
  echo "== $1"
  "$KUBECONFORM" -strict -summary -kubernetes-version "$K8S_SCHEMA_VERSION" \
    -schema-location default -schema-location "$crd_schemas" "$2"
}

# The base, in a namespace (it sets none itself).
mkdir -p "${scratch}/base"
cat >"${scratch}/base/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: omp-validate
resources:
  - ../../base
EOF
"$KUSTOMIZE" build "${scratch}/base" >"${scratch}/base.yaml"
validate "base" "${scratch}/base.yaml"

for overlay in "${root}"/overlays/*/; do
  name="overlays/$(basename "$overlay")"
  out="${scratch}/$(basename "$overlay").yaml"
  "$KUSTOMIZE" build "$overlay" >"$out"
  validate "$name" "$out"
done

# Files kept beside an overlay as alternatives (not in its resources).
validate "overlays/example/httproute.yaml" "${root}/overlays/example/httproute.yaml"
validate "overlays/example/servicemonitor.yaml" "${root}/overlays/example/servicemonitor.yaml"
validate "overlays/example/prometheusrule.yaml" "${root}/overlays/example/prometheusrule.yaml"
validate "overlays/example/networkpolicy-otlp.yaml" "${root}/overlays/example/networkpolicy-otlp.yaml"

# open-mcp-portal-config must be hashed and referenced by both containers.
check_config_refs() { # name, rendered file
  local cm refs
  cm="$(sed -n 's/^  name: \(open-mcp-portal-config-[a-z0-9]\{10\}\)$/\1/p' "$2" | head -n 1)"
  [ -n "$cm" ] || { echo "$1: open-mcp-portal-config has no content hash" >&2; exit 1; }
  # the ConfigMap itself, plus envFrom in the migrate and portal containers
  refs="$(grep -c "name: ${cm}\$" "$2" || true)"
  if [ "$refs" -lt 3 ] || grep -q "name: open-mcp-portal-config\$" "$2"; then
    echo "$1: the Deployment does not reference ${cm} in every container" >&2
    exit 1
  fi
  echo "== $1: config is ${cm}"
}
check_config_refs "base" "${scratch}/base.yaml"
check_config_refs "overlays/example" "${scratch}/example.yaml"
check_config_refs "overlays/smoke" "${scratch}/smoke.yaml"
grep -q "^  APP_URL: https://mcp.example.org\$" "${scratch}/example.yaml" ||
  { echo "overlays/example: APP_URL not merged into the config" >&2; exit 1; }
grep -q "^  METRICS_ADDR: :9090\$" "${scratch}/example.yaml" && grep -q "containerPort: 9090" "${scratch}/example.yaml" ||
  { echo "overlays/example: the metrics port is not wired" >&2; exit 1; }

# No secret values in the manifests: the runtime secret is referenced only
# (the smoke overlay's secrets are created by scripts/k8s-smoke.sh).
if grep -q "^kind: Secret\$" "${scratch}/base.yaml" "${scratch}"/example.yaml "${scratch}"/smoke.yaml; then
  echo "a rendered manifest contains a Secret; secrets must be created outside the base" >&2
  exit 1
fi
echo "all manifests valid"
