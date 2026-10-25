# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/grantd ./cmd/grantd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/grantd /grantd
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/grantd"]
