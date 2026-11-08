FROM php:8.2-cli

LABEL org.opencontainers.image.title="SSRF Field Lab" \
      org.opencontainers.image.description="Local-only SSRF teaching lab with 16 levels"

WORKDIR /opt/ssrf-lab

COPY . /opt/ssrf-lab

RUN sed -i 's/\r$//' /opt/ssrf-lab/docker/entrypoint.sh \
    && chmod 0755 /opt/ssrf-lab/docker/entrypoint.sh \
    && mkdir -p /opt/ssrf-lab/storage

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=6 \
  CMD php -r 'exit(@file_get_contents("http://127.0.0.1:8080/api/health") === false ? 1 : 0);'

ENTRYPOINT ["/opt/ssrf-lab/docker/entrypoint.sh"]
