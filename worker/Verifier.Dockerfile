# Fixed independent reference verifier, separate from builder image.
# The host pins the locally built image ID. Review upstream base provenance.
FROM python:3.12-alpine
WORKDIR /app
COPY verify_worker.py /app/verify_worker.py
USER 65532:65532
ENTRYPOINT ["python3", "/app/verify_worker.py"]
