package = honeypot
default: all

keygen:
	@if [ ! -f rsa.key ]; then ssh-keygen -P "" -f rsa.key && rm rsa.key.pub; fi

get:
	@go get .

install:
	@go install -v .

all: format get install keygen build

run: format
	@go run -race $(package).go

build: test
	go build -v $(package).go

format:
	go fmt *.go

.PHONY: all default install keygen format test
