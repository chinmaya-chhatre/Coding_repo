FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY hookscope ./hookscope

ENV HOOKSCOPE_DB=/data/hookscope.db
VOLUME /data
EXPOSE 8000
CMD ["uvicorn", "hookscope.main:app", "--host", "0.0.0.0", "--port", "8000"]
