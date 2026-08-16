FROM golang:1.27rc2 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/claude-egress-proxy ./cmd/claude-egress-proxy && \
    CGO_ENABLED=0 go build -trimpath -o /out/claude-egress-proxy-state-init ./internal/tools/stateinit && \
    printf 'claude-egress-proxy:x:65532:65532:Claude Egress Proxy:/nonexistent:/sbin/nologin\n' > /out/passwd && \
    printf 'claude-egress-proxy:x:65532:\n' > /out/group

FROM scratch
COPY --from=build /out/claude-egress-proxy /usr/local/bin/claude-egress-proxy
COPY --from=build /out/claude-egress-proxy-state-init /usr/local/bin/claude-egress-proxy-state-init
COPY --from=build /out/passwd /etc/passwd
COPY --from=build /out/group /etc/group
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
EXPOSE 8443
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["/usr/local/bin/claude-egress-proxy","check","health","--address","127.0.0.1:9090"]
ENTRYPOINT ["/usr/local/bin/claude-egress-proxy"]
CMD ["--config","/etc/claude-egress-proxy/config.yaml","serve"]
