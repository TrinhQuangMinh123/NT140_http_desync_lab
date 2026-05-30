FROM python:3.11-slim

WORKDIR /app

# Install Gunicorn + coverage (per-request line tracking, paper §4.2.3-equivalent)
RUN pip install --no-cache-dir gunicorn==21.2.0 coverage==7.4.4

COPY app.py .

EXPOSE 9001

# Single worker (--workers 1) mirrors HDHunter's single-thread target requirement
# --timeout 10 so malformed requests don't hang the process indefinitely
CMD ["gunicorn", "--bind", "0.0.0.0:9001", "--workers", "1", "--timeout", "10", "--log-level", "debug", "app:application"]
