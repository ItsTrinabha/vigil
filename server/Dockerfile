# Vigil SIEM server. Build context is the repository root.
ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    VIGIL_DATA_DIR=/data VIGIL_PORT=8443 VIGIL_SYSLOG_PORT=5514
WORKDIR /opt/vigil/server

COPY server/requirements.txt .
# Behind a TLS-inspecting proxy, pass its CA: docker build --secret id=ca,src=/path/ca.pem ...
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi; \
    pip install --no-cache-dir -r requirements.txt

COPY server/vigil ./vigil
COPY server/rules ./rules
COPY agent/vigil_agent.py agent/install.sh agent/vigil-agent.service /opt/vigil/agent/

RUN useradd --system --uid 10001 --home-dir /data vigil && mkdir -p /data && chown vigil /data
USER vigil
VOLUME /data
EXPOSE 8443 5514/udp 5514/tcp

HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=5 \
  CMD python -c "import ssl,urllib.request,os;s=os.environ.get('VIGIL_TLS','1')!='0';u=('https' if s else 'http')+'://127.0.0.1:8443/api/health';urllib.request.urlopen(u,context=ssl._create_unverified_context() if s else None,timeout=4)"

CMD ["python", "-m", "vigil"]
