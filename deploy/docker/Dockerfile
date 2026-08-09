FROM golang:1.26.5 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/claude-egress-proxy ./cmd/claude-egress-proxy

FROM scratch
COPY --from=build /out/claude-egress-proxy /usr/local/bin/claude-egress-proxy
USER 65532:65532
EXPOSE 8443
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["/usr/local/bin/claude-egress-proxy","check","health","--address","127.0.0.1:9090"]
ENTRYPOINT ["/usr/local/bin/claude-egress-proxy"]
CMD ["--config","/etc/claude-egress-proxy/config.yaml","serve"]
