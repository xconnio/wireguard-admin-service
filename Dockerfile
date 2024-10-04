FROM golang:1.22 AS builder

RUN apt-get update && \
    apt-get install -y \
    iptables \
    wireguard \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN make build-http && strip http-service

FROM ubuntu:22.04

WORKDIR /app

COPY --from=builder /usr/bin/wg-quick /usr/bin/
COPY --from=builder /usr/bin/wg /usr/bin/
COPY --from=builder /app/http-service /app/

CMD ["./http-service"]
