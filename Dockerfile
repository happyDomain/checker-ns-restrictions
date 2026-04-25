FROM golang:1.25-alpine AS builder

ARG CHECKER_VERSION=custom-build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -tags standalone -ldflags "-X main.Version=${CHECKER_VERSION}" -o /checker-ns-restrictions .

FROM scratch
COPY --from=builder /checker-ns-restrictions /checker-ns-restrictions
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/checker-ns-restrictions"]
