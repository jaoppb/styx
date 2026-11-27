# syntax=docker/dockerfile:1

# The static musl binary the release workflow already built, on an empty base. Nothing is
# compiled here and nothing runs, so one build covers every platform without emulation.
#
# The build context holds one binary per platform at <arch>/styx, where <arch> is Docker's
# name for it (amd64, arm64), beside packaging/styx.toml and config/named.root. The `image`
# job in .github/workflows/release.yml lays it out.
FROM scratch
ARG TARGETARCH
COPY --chmod=0755 ${TARGETARCH}/styx /styx

# A working recursor-only default; a file mounted over /etc/styx/styx.toml replaces it.
COPY styx.toml /etc/styx/styx.toml
COPY named.root /etc/styx/named.root

# Unprivileged. Docker lets a container's non-root user bind port 53 on its own network.
USER 65532:65532
EXPOSE 53/udp 53/tcp

# styx drains in-flight queries on SIGINT. It does not handle SIGTERM until Phase 12, and
# a PID 1 without a handler ignores it, so `docker stop` would end in SIGKILL.
STOPSIGNAL SIGINT

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/styx", "health"]

ENTRYPOINT ["/styx"]
CMD ["/etc/styx/styx.toml"]
