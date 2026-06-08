IMAGE ?= ghcr.io/malvinpratama/iam-go-authatest

build:   ## compile
	go build ./...
test:    ## unit tests
	go test ./...
vet:     ## static checks
	go vet ./...
docker:  ## build the service image
	docker build -t $(IMAGE) .
