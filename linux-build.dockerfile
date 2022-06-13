FROM amazonlinux:2
RUN yum update -y && yum groupinstall -y 'Development Tools' && yum install -y bzip2 openssl-devel tar zip
COPY ["rustup-init", "/tmp/"]
RUN /tmp/rustup-init -y --default-toolchain nightly --profile minimal
ENV PATH=/root/.cargo/bin:$PATH
RUN mkdir /letsencrypt-certs-aws
COPY ["Cargo.lock", "Cargo.toml", "/letsencrypt-certs-aws/"]
COPY ["src", "/letsencrypt-certs-aws/src/"]
WORKDIR /letsencrypt-certs-aws
RUN pwd
RUN ls -laR
RUN cargo build --release
WORKDIR /letsencrypt-certs-aws/target/release
RUN ln letsencrypt-certs-aws bootstrap \
    && zip -9 /letsencrypt-certs-aws-$(uname -m | sed -e 's/aarch64/arm64/').zip bootstrap
VOLUME /export
