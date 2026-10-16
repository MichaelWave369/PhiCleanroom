# Reference probe only, NOT a builder or production-hardened base.
# Pin the base digest after assessing its provenance; the runner requires
# a SHA-256-pinned image ID regardless of this mutable base-image tag.
FROM python:3.12-alpine
WORKDIR /app
COPY probe.py /app/probe.py
USER 65532:65532
ENTRYPOINT ["python3", "/app/probe.py"]
