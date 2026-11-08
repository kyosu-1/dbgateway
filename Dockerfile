# syntax=docker/dockerfile:1
# Build: the PostgreSQL parser (pg_query_go) needs cgo.
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/dbgw ./cmd/dbgw

# Runtime: glibc-based distroless image, non-root.
FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=build /out/dbgw /usr/local/bin/dbgw
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/dbgw"]
CMD ["serve", "--config", "/etc/dbgateway/dbgateway.yaml"]
