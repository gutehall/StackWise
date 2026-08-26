# StackWise — AWS infrastructure scanner
FROM python:3.11-slim-bookworm

# WeasyPrint deps for PDF reports (per https://doc.courtbouillon.org/weasyprint/)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 libffi-dev \
    libcairo2 libgdk-pixbuf-2.0-0 shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

RUN useradd --create-home --shell /bin/bash stackwise && \
    mkdir -p /data && chown stackwise:stackwise /data

ENV STACKWISE_DATA_DIR=/data
ENV PYTHONUNBUFFERED=1
VOLUME /data

USER stackwise

ENTRYPOINT ["stackwise"]
CMD ["--help"]
