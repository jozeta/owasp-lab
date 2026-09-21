FROM python:3.12-slim

RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --create-home appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

# 4 workers, not 2: /a03/xxe-ssrf makes a self-referential HTTP request and
# needs a free worker while its own is blocked handling the request.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--preload", "--config", "gunicorn.conf.py", "wsgi:application"]
