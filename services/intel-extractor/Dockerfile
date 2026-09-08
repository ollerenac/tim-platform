FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 && rm -rf /var/lib/apt/lists/*
# chown /data BEFORE the named volume is first created so Docker seeds the volume with
# uid 1000 ownership — collector_state.json is written here by the non-root process.
RUN useradd -u 1000 -m appuser && mkdir -p /data && chown 1000:1000 /data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER appuser
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8004"]
