FROM python:3.12-slim

WORKDIR /app/backend

# System tools needed by Scapy and networking introspection.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend /app/backend

EXPOSE 5000

CMD ["python", "app.py", "auto"]
