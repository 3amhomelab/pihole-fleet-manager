FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    sshpass \
    iputils-ping \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY workers/ workers/
COPY templates/ templates/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

ARG APP_VERSION=dev
ENV APP_VERSION=$APP_VERSION

VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["./entrypoint.sh"]
CMD ["python", "app.py"]
