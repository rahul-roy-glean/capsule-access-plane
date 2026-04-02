.PHONY: lint vet test cover build docker docker-build docker-push ci clean

PROJECT ?= $(shell gcloud config get-value project)
REGION  ?= us-central1
IMAGE   := $(REGION)-docker.pkg.dev/$(PROJECT)/capsule/access-plane
TAG     ?= latest

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

docker-build:
	docker build --platform linux/amd64 -t $(IMAGE):$(TAG) .

docker-push: docker-build
	docker push $(IMAGE):$(TAG)

ci: lint vet test build

clean:
	rm -f capsule-access-plane coverage.out *.db
