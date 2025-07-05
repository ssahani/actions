# Stage 1: Build Go binary statically
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache \
    bash \
    ca-certificates \
    cryptsetup \
    device-mapper \
    e2fsprogs \
    gcc \
    git \
    musl-dev \
    util-linux \
    xfsprogs

COPY . /src
WORKDIR /src/writefile

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 GOOS=linux \
    go build -a \
    -ldflags "-linkmode external -extldflags '-static' -s -w" \
    -o writefile

# Stage 2: Create minimal runtime image
FROM alpine:3.19

RUN apk add --no-cache \
    cryptsetup \
    e2fsprogs \
    util-linux \
    sudo \
 && adduser -D appuser \
 && echo 'appuser ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/appuser \
 && chmod 0440 /etc/sudoers.d/appuser \
 && mkdir -p /mnt/action /mnt/boot /tmp/mnt \
 && chown appuser:appuser /mnt /mnt/* /tmp/mnt

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /src/writefile/writefile /usr/bin/

USER appuser
WORKDIR /home/appuser
ENTRYPOINT ["/usr/bin/writefile"]
