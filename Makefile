.PHONY: lint vet test cover build docker ci clean

lint:
	golangci-lint run ./...

vet:
	go vet ./...

test:
	go test -race ./...

cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

build:
	go build -o capsule-access-plane .

docker:
	docker build -t capsule-access-plane .

ci: lint vet test build

clean:
	rm -f capsule-access-plane coverage.out *.db
