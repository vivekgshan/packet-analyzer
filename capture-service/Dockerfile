FROM python:3.12-slim

# Install debugging and network tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tcpdump curl iproute2 iputils-ping net-tools && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements specific to this service
COPY capture-service/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the service code explicitly
COPY capture-service/capture.py /app/capture.py

ENTRYPOINT ["python3", "capture.py"]
