ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}

COPY --chown=65534:65534 agent.py /opt/sova/agent
RUN chmod 0555 /opt/sova/agent

USER 65534:65534
ENTRYPOINT ["/opt/sova/agent"]

