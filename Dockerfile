FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY hookscope ./hookscope

# Run as an unprivileged user; /data holds the SQLite database (mount a volume there).
RUN useradd --create-home --uid 10001 hookscope && mkdir -p /data && chown hookscope /data
USER hookscope

ENV HOOKSCOPE_DB=/data/hookscope.db \
    PORT=8000
VOLUME /data
EXPOSE 8000

# PORT is set by hosts such as Render. --proxy-headers makes the app see the public
# scheme and host behind a load balancer, which URL-signed providers (Twilio) need.
CMD ["sh", "-c", "exec uvicorn hookscope.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
