default: build
build: build-x86_64 build-arm64
build-x86_64: lambda-x86_64.zip
build-arm64: lambda-arm64.zip

SOURCES = Cargo.toml Cargo.lock src/*.rs

lambda-%.zip: $(SOURCES)
	ARCH=$(shell echo $@ | sed -e 's/^lambda-\(.*\)\.zip/\1/'); \
case "$$ARCH" in \
  x86_64 ) SOURCE=amazonlinux:2;; \
  arm64 ) SOURCE=arm64v8/amazonlinux:2;; \
  * ) echo "Unknown arch $$ARCH" 1>&2; exit 1;; \
esac; \
BUILD_ARGS="$(BUILD_ARGS)"; \
if [ -f .build-nocache-$$ARCH ]; then \
	rm .build-nocache-$$ARCH; \
	BUILD_ARGS="$$BUILD_ARGS --no-cache"; \
fi; \
docker build --progress=plain --file linux-build.dockerfile \
  --build-arg SOURCE="$$SOURCE" --build-arg ARCH="$$ARCH" \
  --tag "letsencrypt-certs-aws:$$ARCH" $$BUILD_ARGS . && \
mkdir -p ./export && \
docker run --rm --mount type=bind,source=$${PWD}/export,target=/export \
  "letsencrypt-certs-aws:$$ARCH" cp /"lambda-$$ARCH.zip" /export/ && \
mv "./export/lambda-$$ARCH.zip" .

clean:
	rm -rf lambda*.zip target
	touch .build-nocache-arm64 .build-nocache-x86_64

.PHONY: default build build-x86-64 build-arm64 clean