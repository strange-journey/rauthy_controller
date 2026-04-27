FROM cgr.dev/chainguard/static
COPY --chown=nonroot:nonroot ./controller /app/controller
ENTRYPOINT ["/app/controller"]