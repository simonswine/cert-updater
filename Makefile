
all: minify

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64       go build -a -tags netgo -ldflags '-s -w' -o cert-updater-linux-amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -a -tags netgo -ldflags '-s -w' -o cert-updater-linux-arm7

minify: build
	upx --brute cert-updater-linux-amd64 cert-updater-linux-arm7
