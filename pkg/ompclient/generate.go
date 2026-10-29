package ompclient

// The client and its types are generated from api/openapi.yaml, keeping only
// the operations that accept automation tokens (the ones with an
// x-omp-token-scopes extension; see overlay.yaml). Regenerate with
// `make generate`; `make check-generated` fails when this is stale.
//
//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../../api/openapi.yaml
