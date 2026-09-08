FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 && rm -rf /var/lib/apt/lists/*
RUN useradd -u 1000 -m appuser
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Drop root: this service only talks to Redis/ES/OpenCTI over the network (no local writes).
USER appuser
CMD ["python", "main.py"]
