.PHONY: build test fmt
export GOTOOLCHAIN = go1.26.10
export GOFLAGS = -p=2
build:
	go build -o /tmp/terraform-provider-omp .
test:
	go test -race -count=1 -timeout=20m ./...
fmt:
	gofmt -w main.go internal

# Opt-in CI/dev gate. Use only a NEW owned loopback PG17 cluster, /postgres.
# The nested acceptance module intentionally stays out of ordinary ./... tests.
.PHONY: test-acceptance
test-acceptance:
	@test "$$TF_ACC" = 1 || (echo 'Set TF_ACC=1 explicitly'; exit 1)
	@test "$$OMP_TEST_REQUIRE_DB" = 1 || (echo 'Set OMP_TEST_REQUIRE_DB=1 explicitly'; exit 1)
	@test -n "$$OMP_TEST_DATABASE_URL" || (echo 'Set owned loopback PG17 URL'; exit 1)
	@test -n "$$OMP_TERRAFORM_CLI" || (echo 'Set verified Terraform executable'; exit 1)
	@set -eu; for mode in 0 1; do \
	  cd acceptance; \
	  OMP_TEST_SPLIT_ROLES=$$mode go test -race -v -count=1 -timeout=20m ./...; \
	  cd ..; \
	done
