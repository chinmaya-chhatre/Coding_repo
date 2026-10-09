FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY hookscope ./hookscope
COPY deploy/entrypoint.sh /usr/local/bin/hookscope-entrypoint

# The app runs as this unprivileged user; /data holds the SQLite database.
RUN useradd --create-home --uid 10001 hookscope && mkdir -p /data && chown hookscope /data

ENV HOOKSCOPE_DB=/data/hookscope.db \
    PORT=8000
VOLUME /data
EXPOSE 8000

# The entrypoint fixes ownership of a root-owned mounted volume, then drops to `hookscope`.
# It listens on $PORT (set by hosts such as Render) and trusts X-Forwarded-* headers so
# URL-signed providers (Twilio) verify behind a TLS-terminating proxy.
ENTRYPOINT ["hookscope-entrypoint"]
