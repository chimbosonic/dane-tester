FROM rust:slim

RUN mkdir -p /build

COPY . /build

WORKDIR /build/server

RUN apt-get update -y && apt-get install -y curl && cargo build --release

FROM rust:slim

RUN mkdir -p /opt

COPY --from=0 /build/target/release/dane-tester-server /opt/dane-tester-server

RUN chmod +x /opt/dane-tester-server
WORKDIR /opt

EXPOSE 7070
ENV DNS_SERVER="86.54.11.100"
ENTRYPOINT ["/opt/dane-tester-server"]
