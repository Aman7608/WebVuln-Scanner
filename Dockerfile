# WebVuln Scanner - one image used for both the web app and the scan worker.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WEBVULN_MODE=public \
    WEBVULN_HOST=0.0.0.0 \
    WEBVULN_PORT=8000 \
    WEBVULN_BEHIND_PROXY=1

WORKDIR /app

# Run as a normal user, never as root
RUN useradd --create-home --uid 10001 webvuln

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=webvuln:webvuln . .
USER webvuln

EXPOSE 8000
# The web app. docker-compose.yml runs "python worker.py" for the worker container.
CMD ["python", "serve.py"]
