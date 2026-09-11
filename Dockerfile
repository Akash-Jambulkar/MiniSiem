FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY rules ./rules
COPY data ./data

ENV PYTHONUNBUFFERED=1
ENV MINI_SIEM_EVENTS_OUT=/app/data/output/events.jsonl
ENV MINI_SIEM_ALERTS_OUT=/app/data/output/alerts.jsonl

EXPOSE 8501

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "src.main", "--input", "data/samples/auth.log", "--source", "ssh", "--no-enrich"]
