default: build
build: build-aarch64
build-x86_64: letsencrypt-certs-aws-x86_64.zip
build-aarch64: letsencrypt-certs-aws-aarch64.zip

SOURCES = Cargo.toml Cargo.lock src/*.rs src/auth/*.rs

letsencrypt-certs-aws-%.zip: $(SOURCES)
	./arch-build $(shell echo $@ | sed -e 's/^letsencrypt-certs-aws-\(.*\)\.zip/\1/')

clean:
	rm -rf lambda*.zip target
	touch .build-nocache

.PHONY: default build build-aarch64 build-x86-64 clean