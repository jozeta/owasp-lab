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

# 4 workers, not 2: /a03/xxe-ssrf, and A10's webhook-tester, port-scan-demo,
# pdf-generator, import-avatar, and mirror-fetcher routes all make
# self-referential/outbound HTTP requests and need a free worker while their
# own is blocked handling the request.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--preload", "--config", "gunicorn.conf.py", "wsgi:application"]
