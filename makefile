GOPATH ?= /home/vagrant/go

default: x86_64

all: x86_64 x86_32 arm_32

x86_64:
	GOARC=amd64 GOOS=linux go build -o coordnode_x86_64

x86_32:
	GOARCH=386 GOOS=linux go build -o coordnode_x86_32

arm_32:
	GOARM=7	GOARCH=arm GOOS=linux go build -o coordnode_arm_32

install:
	go install

check: test fmt

test:
	go test ./...

fmt:
	go fmt ./...

clean:
	go clean -i ; rm -f coordnode_*
