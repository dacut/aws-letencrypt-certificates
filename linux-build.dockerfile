ARG SOURCE
FROM $SOURCE
RUN yum update -y \
    && amazon-linux-extras install -y rust1 \
    && yum install -y bzip2 openssl-devel tar zip \
    && mkdir /letsencrypt-certs-aws
COPY Cargo.lock Cargo.toml /letsencrypt-certs-aws/
COPY src /letsencrypt-certs-aws/src/
WORKDIR /letsencrypt-certs-aws
RUN ls -laR
RUN cargo build
WORKDIR /letsencrypt-certs-aws/target/debug
RUN pwd
ARG ARCH
RUN ln letsencrypt-certs-aws bootstrap \
    && zip -9 /lambda-$ARCH.zip bootstrap
VOLUME /export