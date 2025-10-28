FROM golang:1.23-bullseye AS builder
WORKDIR /src

# Copy shared library first
COPY shared/ ./shared/

# Copy service files
COPY ocsp/go.mod ocsp/go.sum ./ocsp/
WORKDIR /src/ocsp
RUN go mod download

WORKDIR /src
COPY ocsp/ ./ocsp/
WORKDIR /src/ocsp
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/ocsp ./cmd/ocsp

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/ocsp /usr/local/bin/ocsp
COPY ocsp/config/ /config/
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/ocsp"]
