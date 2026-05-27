FROM python:3.11-slim AS builder

WORKDIR /build
COPY . .
RUN pip install build && python -m build

FROM python:3.11-slim

RUN groupadd -r aishield && useradd -r -g aishield -d /app -s /sbin/nologin aishield

WORKDIR /app

COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

RUN mkdir -p /app/data && chown aishield:aishield /app/data
VOLUME ["/app/data"]

USER aishield

ENTRYPOINT ["aishield"]
CMD ["--help"]
