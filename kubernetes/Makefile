IMAGE ?= ghcr.io/aojea/agents.net/dra-agents-net:latest

.PHONY: build test vet fmt image smoke

build:
	go build ./cmd/...

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

image:
	docker build -t $(IMAGE) .

smoke:
	./test/smoke.sh
