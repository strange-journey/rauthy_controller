FROM cgr.dev/chainguard/static

ARG TARGETARCH
COPY --chown=nonroot:nonroot ./dist/linux/${TARGETARCH}/controller /app/controller

ENTRYPOINT ["/app/controller"]
