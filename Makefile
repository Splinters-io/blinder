VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: build build-diff test test-functional clean release lint

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o blinder ./cmd/blinder

build-diff:
	CGO_ENABLED=0 go build -o blinder-diff ./cmd/blinder-diff

test:
	go test -race -count=1 ./...

test-functional:
	go test -tags functional -race -count=1 -timeout 120s ./tests/functional

lint:
	go vet ./...

clean:
	rm -f blinder blinder-*

release: clean
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o blinder-linux-amd64   ./cmd/blinder
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o blinder-linux-arm64   ./cmd/blinder
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o blinder-darwin-amd64  ./cmd/blinder
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o blinder-darwin-arm64  ./cmd/blinder
