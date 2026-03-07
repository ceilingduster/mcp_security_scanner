FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ORCORUS_REPORTS_DIR=/app/reports \
    ORCORUS_WORK_DIR=/app/repos

WORKDIR /app

RUN apt-get update \
    && apt-get install --yes --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /app/reports /app/repos

CMD ["python", "server.py"]
