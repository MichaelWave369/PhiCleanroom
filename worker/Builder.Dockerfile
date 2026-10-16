# Explicitly reference-only. The production runner pins this built image ID.
# Base image tag is not digest pinned yet; use reviewed digest in stricter systems.
FROM python:3.12-alpine
WORKDIR /app
COPY reference_builder.py /app/reference_builder.py
USER 65532:65532
ENTRYPOINT ["python3", "/app/reference_builder.py"]
