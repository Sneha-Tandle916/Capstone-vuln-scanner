FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scanner/ scanner/
COPY config.yaml .

ENTRYPOINT ["python", "-m", "scanner.scan"]
CMD ["--help"]
