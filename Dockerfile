# syntax=docker/dockerfile:1

FROM golang:1.24.1 AS build
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/api ./cmd/api && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/worker ./cmd/worker && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/kuberhealthy-api-check ./cmd/kuberhealthy-api-check

FROM gcr.io/distroless/static-debian12 AS api
WORKDIR /app
COPY --from=build /out/api /app/api
EXPOSE 8080
ENTRYPOINT ["/app/api"]

FROM gcr.io/distroless/static-debian12 AS worker
WORKDIR /app
COPY --from=build /out/worker /app/worker
ENTRYPOINT ["/app/worker"]

FROM gcr.io/distroless/static-debian12 AS kuberhealthy-api-check
WORKDIR /app
COPY --from=build /out/kuberhealthy-api-check /app/kuberhealthy-api-check
ENTRYPOINT ["/app/kuberhealthy-api-check"]
