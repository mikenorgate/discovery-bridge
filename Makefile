.PHONY: test reference build check artifacts container

VERSION ?= 0.0.0-dev
ARCH ?= $(shell go env GOARCH)

test:
	go test -race -shuffle=on ./...

reference:
	cd reference/python && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v

build:
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -o dist/discovery-bridge ./cmd/discovery-bridge

artifacts:
	python3 packaging/build.py compile --version $(VERSION)
	python3 packaging/build.py package --version $(VERSION) --arch $(ARCH)
	python3 tests/check_artifacts.py --arch $(ARCH)

container:
	python3 packaging/container.py prepare --arch $(ARCH)
	python3 packaging/container.py build --arch $(ARCH)
	python3 tests/check_container.py --arch $(ARCH)

check:
	python3 tests/check_public.py
	test -z "$$(gofmt -l cmd internal registry)"
	go vet ./...
