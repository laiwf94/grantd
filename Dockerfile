# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/wicket ./cmd/wicket

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/wicket /wicket
USER nonroot:nonroot
EXPOSE 4180
ENTRYPOINT ["/wicket"]
