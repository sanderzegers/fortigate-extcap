BUILD_DATE := $(shell date -u '+%Y-%m-%d %H:%M:%S UTC')

build:
	go build -ldflags "-X 'main.buildDate=$(BUILD_DATE)'" -o fortidump .

build-windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X 'main.buildDate=$(BUILD_DATE)'" -o fortidump.exe .
