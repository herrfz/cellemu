GOPATH ?= /home/vagrant/go

amd64:
	go build

arm:
	GOARM=7	GOARCH=arm GOOS=linux go build -o coordnode_arm

i386:
	GOARCH=386 GOOS=linux go build -o coordnode_i386

all: amd64 arm i386

install:
	go install

check: test fmt

test:
	go test ./...

fmt:
	go fmt ./...

clean:
	go clean -i ; rm -f coordnode_*
