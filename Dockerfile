FROM golang:1.23 AS zlint-builder

ARG ZLINT_VERSION=v3.6.4

RUN GOBIN=/out go install github.com/zmap/zlint/v3/cmd/zlint@${ZLINT_VERSION}


FROM python:3.11-slim

WORKDIR /app

COPY --from=zlint-builder /out/zlint /usr/local/bin/zlint

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "ct_analyzer", "api"]
