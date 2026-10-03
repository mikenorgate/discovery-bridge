.PHONY: test build tools check artifacts container

VERSION ?= 0.0.0-dev
ARCH ?= $(shell go env GOARCH)

test:
	go test -race -shuffle=on ./...

build:
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -o dist/discovery-bridge ./cmd/discovery-bridge

tools:
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -o dist/release-tools ./cmd/release-tools

artifacts: tools
	dist/release-tools compile --version $(VERSION)
	dist/release-tools package --version $(VERSION) --arch $(ARCH)
	dist/release-tools check-artifacts --arch $(ARCH)

container: tools
	dist/release-tools container-prepare --arch $(ARCH)
	dist/release-tools container-build --arch $(ARCH)
	dist/release-tools check-container --arch $(ARCH)

check:
	go run ./cmd/release-tools check-source
	test -z "$$(gofmt -l cmd internal registry)"
	go vet ./...
