ARG branch=latest
ARG base=cccs/assemblyline-v4-service-base
FROM $base:$branch

ENV SERVICE_PATH=speakeasy_service.speakeasy_service.Speakeasy

USER root
WORKDIR /opt/al_service

# Speakeasy's own dependencies (unicorn, capstone, pefile, pycryptodome, lznt1,
# pydantic, rich) ship prebuilt wheels for common platforms, but gcc/libc-dev are
# installed here too in case any of them need to build from sdist for this image's
# exact Python/arch combination (matches the build tooling the upstream Speakeasy
# Dockerfile itself installs for the same reason).
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc-dev \
    && rm -rf /var/lib/apt/lists/*

COPY speakeasy_service speakeasy_service
COPY service_manifest.yml .
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir ./speakeasy_service/vendor/speakeasy-src

ARG version=4.7.4.stable1
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml
USER assemblyline
