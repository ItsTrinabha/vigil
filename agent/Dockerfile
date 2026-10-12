# Vigil agent as a container: reads the host's /var/log (mounted read-only),
# host processes (pid: host) and the lab log directory used by the demo.
ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}
ENV PYTHONUNBUFFERED=1 VIGIL_STATE_DIR=/state
WORKDIR /opt/vigil
COPY agent/vigil_agent.py scripts/lab_replay.py ./
VOLUME /state
# Wait for the server's certificate to exist on the shared volume, then pin it.
CMD ["sh", "-c", "while [ -n \"$VIGIL_CA_FILE\" ] && [ ! -s \"$VIGIL_CA_FILE\" ]; do echo 'waiting for server certificate'; sleep 2; done; exec python vigil_agent.py"]
