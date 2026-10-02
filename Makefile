.PHONY: test reference build check

test:
	go test -race -shuffle=on ./...

reference:
	cd reference/python && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v

build:
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -o dist/discovery-bridge ./cmd/discovery-bridge

check:
	python3 tests/check_public.py
	test -z "$$(gofmt -l cmd internal registry)"
	go vet ./...
