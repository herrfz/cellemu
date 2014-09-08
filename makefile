all: local

local:
	go build

bb:
	CC=arm-none-linux-gnueabi-gcc GOARM=7 GOARCH=arm GOOS=linux CGO_ENABLED=1 go build -ldflags -L/opt/arm/lib -o arm_coordnode

install:
	go install

install_bb:
	CC=arm-none-linux-gnueabi-gcc GOARM=7 GOARCH=arm GOOS=linux CGO_ENABLED=1 go install -o arm_coordnode

clean:
	go clean ; rm ../../../../bin/coordnode

clean_bb:
	go clean ; rm ../../../../bin/linux_arm/coordnode
