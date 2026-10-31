.PHONY: build test fmt
export GOTOOLCHAIN = go1.26.10
export GOFLAGS = -p=2
build:
	go build -o /tmp/terraform-provider-omp .
test:
	go test -race -count=1 -timeout=20m ./...
fmt:
	gofmt -w main.go internal
