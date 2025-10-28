.PHONY: build test lint docker run-local clean

build:
	go build -o bin/ocsp ./cmd/ocsp

test:
	go test ./... -v

lint:
	golangci-lint run ./...

docker:
	docker build -t gigvault/ocsp:local .

run-local: docker
	../infra/scripts/deploy-local.sh ocsp

clean:
	rm -rf bin/
	go clean
