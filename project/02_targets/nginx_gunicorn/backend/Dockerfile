FROM python:3.11-slim

WORKDIR /app

# Install Gunicorn
RUN pip install --no-cache-dir gunicorn==21.2.0

COPY app.py .

EXPOSE 9001

# Single worker (--workers 1) mirrors HDHunter's single-thread target requirement
# --timeout 10 so malformed requests don't hang the process indefinitely
CMD ["gunicorn", "--bind", "0.0.0.0:9001", "--workers", "1", "--timeout", "10", "--log-level", "debug", "app:application"]
