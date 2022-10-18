.PHONY: all build check dev image stats test vendor

all: build

build:
	go install .

check:
	bin/check

dev:
	convox start

image:
	docker build -t convox/certbot .

stats:
	cloc . --exclude-dir=vendor

test: check
	go test ./...

vendor:
	go get -u github.com/kardianos/govendor
	govendor fetch +outside
	govendor remove +unused
