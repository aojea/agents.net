IMAGE ?= ghcr.io/aojea/agents.net/dra-agents-net:latest
STACK_IMAGE ?= ghcr.io/aojea/agents.net/agents-net-stack:latest

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
	docker build -t $(STACK_IMAGE) -f Dockerfile.stack .

smoke:
	./test/smoke.sh
