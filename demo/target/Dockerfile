# Vulnerable demo target, built and run UNDER the RASP LD_PRELOAD shim.
# DEMO ONLY.
FROM python:3.12-slim

# gcc + make to build the RASP preload shim. (We use the psycopg2 *binary* wheel,
# which bundles libpq — so the channel-B DB hook is not active here; the RASP
# demo is carried by channel A: RCE / LFI / SSRF, which need no DB at all.)
# gcc + make + libc6-dev to compile the RASP preload shim self-contained inside
# the image (libc6-dev supplies string.h etc.; without it --no-install-recommends
# leaves no C headers and the shim silently falls back to host-built artifacts).
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make libc6-dev && rm -rf /var/lib/apt/lists/*

# Python deps first (cached) so RASP shim changes below are fast rebuilds.
WORKDIR /app
COPY demo/target/app.py /app/app.py
RUN pip install --no-cache-dir flask psycopg2-binary

# Plant a fake secret file so LFI is demonstrable without touching the real one.
RUN echo "root:x:0:0:DEMO FAKE passwd:/root:/bin/false" > /etc/passwd.demo

# Build the RASP preload library LAST so iterating on the shim is fast.
WORKDIR /opt/rasp
COPY rasp/ /opt/rasp/
# `make clean` first so a stale librasp_preload.so / *.o copied in from the host
# build tree can never shadow a real rebuild (channel B is excluded by default).
RUN make clean && make

WORKDIR /app
ENV RASP_SOCKET=/run/waf-rasp.sock
ENV LD_PRELOAD=/opt/rasp/librasp_preload.so
# Observe mode: the RASP DETECTS, reports, and (via the trust engine) BANS every
# exploit, but does not kill the in-flight syscall — so a fragile dev backend
# stays healthy. Set RASP_ENFORCE=1 / RASP_DB_ENFORCE=1 for true inline blocking
# against a production-grade backend.
ENV RASP_ENFORCE=0
ENV RASP_DB_ENFORCE=0

EXPOSE 9090
CMD ["python", "app.py"]
