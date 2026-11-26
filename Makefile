DRIVER_IMAGE ?= ghcr.io/aojea/agents.net/kube-net-driver:latest
STACK_IMAGE ?= ghcr.io/aojea/agents.net/kube-netstack:latest
PEP_IMAGE ?= ghcr.io/aojea/agents.net/kube-pep:latest
INBOUND_IMAGE ?= ghcr.io/aojea/agents.net/kube-inbound:latest

.PHONY: build test vet fmt image smoke test-envoy test-gvisor test-microvm

build:
	go build ./cmd/...

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

image:
	docker build -t $(DRIVER_IMAGE) -f Dockerfile.kube-net-driver .
	docker build -t $(STACK_IMAGE) -f Dockerfile.kube-netstack .
	docker build -t $(PEP_IMAGE) -f Dockerfile.kube-pep .
	docker build -t $(INBOUND_IMAGE) -f Dockerfile.kube-inbound .

smoke:
	./test/smoke.sh

test-envoy:
	./test/envoy/run.sh

test-gvisor:
	./test/gvisor/run.sh

test-microvm:
	./test/microvm/run.sh
