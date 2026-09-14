FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download InsightFace buffalo_sc model during build so it's cached in image
# This avoids ~100MB download on every cold start
RUN python -c "\
import insightface; \
app = insightface.app.FaceAnalysis(name='buffalo_sc', providers=['CPUExecutionProvider']); \
app.prepare(ctx_id=-1, det_size=(640,640)); \
print('InsightFace buffalo_sc model cached')"

COPY . .

RUN mkdir -p /app/db /app/seed_photos

EXPOSE 8000

CMD ["sh", "-c", "uvicorn api:app --host 0.0.0.0 --port ${PORT:-8000}"]
