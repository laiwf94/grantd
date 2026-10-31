# syntax=docker/dockerfile:1
# toolgate is part of the root module; build from the repository root:
#   docker build -f toolgate/Dockerfile .
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/toolgate ./toolgate/cmd/toolgate \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mcpfake ./toolgate/cmd/mcpfake \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/toolgate /toolgate
COPY --from=build /out/mcpfake /mcpfake
# Audit log and tool pins live here; owned by nonroot so a fresh volume is writable.
COPY --from=build --chown=nonroot:nonroot /out/data /data
USER nonroot:nonroot
ENV TOOLGATE_ADDR=0.0.0.0:8080
EXPOSE 8080 8081
ENTRYPOINT ["/toolgate"]
