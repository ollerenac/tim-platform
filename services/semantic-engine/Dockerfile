FROM python:3.12-slim
# ponytail: pycti==6.4.11 imports python-magic which requires libmagic.so — same as intel-extractor
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 && rm -rf /var/lib/apt/lists/*
RUN useradd -u 1000 -m appuser
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Drop root: talks only to ChromaDB/Ollama/OpenCTI over the network (no local writes).
USER appuser
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
