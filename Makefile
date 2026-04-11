VERSION := 0.1.0
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -s -w"
DIST := dist

.PHONY: build-all build-linux-amd64 build-linux-arm64 build-windows-amd64 clean test

build-all: build-linux-amd64 build-linux-arm64 build-windows-amd64

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/arktis-agent-linux-amd64 ./cmd/arktis-agent

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/arktis-agent-linux-arm64 ./cmd/arktis-agent

build-windows-amd64:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/arktis-agent-windows-amd64.exe ./cmd/arktis-agent

test:
	go test ./...

clean:
	rm -rf $(DIST)
