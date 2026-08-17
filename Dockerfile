FROM golang:1.25-alpine AS builder
WORKDIR /src

# Cached separately from the rest of the source so dependency downloads
# aren't repeated on every code change.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/iam-server ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && \
    addgroup -S iam && adduser -S iam -G iam
COPY --from=builder /out/iam-server /usr/local/bin/iam-server

USER iam
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/iam-server"]