FROM python:3.12-slim

RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --create-home appuser

# ImageMagick 6.9.2-10 -- the last release before CVE-2016-3714
# ("ImageTragick") was fixed in 6.9.3-10. Compiled from a vendored source
# tarball (not fetched at build time -- ImageMagick's own release archive
# no longer resolves, and no single external mirror is guaranteed to stay
# up long-term) since Debian's packaged `imagemagick` is a modern, patched
# build. This is the ONLY ImageMagick on this image -- the Debian package
# is never installed, so `convert` on PATH always resolves to this exact
# vulnerable build. `curl` is required at RUNTIME, not just build time: it
# is the actual delegate binary ImageMagick's vulnerable HTTPS coder shells
# out to -- see app/categories/a06_vulnerable_components/routes.py.
COPY vendor/ImageMagick-6.9.2-10.tar.xz /tmp/imagemagick.tar.xz
RUN echo "da2f6fba43d69f20ddb11783f13f77782b0b57783dde9cda39c9e5e733c2013c  /tmp/imagemagick.tar.xz" | sha256sum -c - \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential curl xz-utils \
        libjpeg-dev libpng-dev libtiff-dev zlib1g-dev pkg-config \
    && cd /tmp && tar xJf imagemagick.tar.xz \
    && cd ImageMagick-6.9.2-10 \
    && ./configure --without-x --disable-openmp --without-perl \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig \
    && cd / && rm -rf /tmp/imagemagick.tar.xz /tmp/ImageMagick-6.9.2-10 \
    && rm -rf /var/lib/apt/lists/*

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
