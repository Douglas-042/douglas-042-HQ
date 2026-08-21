FROM python:3.12-slim

LABEL org.opencontainers.image.title="Douglas-042 Hunt Console" \
      org.opencontainers.image.description="Incident response and threat hunting platform" \
      org.opencontainers.image.vendor="OnBT / Behind24 Blue Team"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

# Dependencies first so code edits don't invalidate the wheel layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/    ./app/
COPY static/ ./static/
COPY agent/  ./agent/

# Run unprivileged; the data volume is the only writable path we need.
RUN useradd --system --uid 10001 --create-home douglas \
 && mkdir -p /srv/data/bundles \
 && chown -R douglas:douglas /srv

USER douglas
ENV DOUGLAS_DATA_DIR=/srv/data
VOLUME ["/srv/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=4).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
