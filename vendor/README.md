# vendor/

Third-party source vendored into this repo because it's a specific *historical,
intentionally-vulnerable* release no longer reliably available from any single
upstream mirror.

## ImageMagick-6.9.2-10.tar.xz

- **Why it's here:** the last ImageMagick release before the CVE-2016-3714
  ("ImageTragick") fix landed in 6.9.3-10. Debian/Ubuntu's packaged
  `imagemagick` is a modern, patched build, and ImageMagick's own release
  archive server no longer resolves — this exact tarball was fetched from
  `https://ftp.icm.edu.pl/pub/unix/graphics/ImageMagick/releases/` (a
  long-running academic FOSS mirror) and is vendored here so the Docker
  build never depends on that (or any other) mirror staying up.
- **SHA-256:** `da2f6fba43d69f20ddb11783f13f77782b0b57783dde9cda39c9e5e733c2013c`
- **Used by:** the Dockerfile, which compiles it from source and installs
  it as `/usr/local/bin/convert` — the ONLY ImageMagick on this image. A06's
  ImageTragick examples (`app/categories/a06_vulnerable_components/routes.py`)
  shell out to this exact binary.
- Genuinely vulnerable — verified empirically before this file was added:
  a crafted MVG payload (disguised with a `.jpg` extension) achieves real
  command execution via this build's HTTPS delegate (`curl`).
