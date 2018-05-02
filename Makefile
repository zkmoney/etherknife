.PHONY: build

build:
	xgo --deps=https://gmplib.org/download/gmp/gmp-6.0.0a.tar.bz2 \
		--targets=linux/amd64 \
		--dest=./build \
		./cmd/etherknife

build-remote:
	xgo --deps=https://gmplib.org/download/gmp/gmp-6.0.0a.tar.bz2 \
		--targets=linux/amd64 \
		--dest=./build \
		github.com/zkmoney/etherknife/cmd/etherknife