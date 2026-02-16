FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone https://github.com/dennisgk/py-simple-ms.git

WORKDIR /opt/py-simple-ms/py-simple-ms-proxy
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8765
CMD ["python", "proxy.py"]
