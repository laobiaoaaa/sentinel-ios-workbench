FROM docker.1ms.run/library/python:3.12-slim-bookworm
ARG PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=7801
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --index-url "$PIP_INDEX_URL" -r requirements.txt \
    && python -m venv /opt/frida17 \
    && /opt/frida17/bin/pip install --no-cache-dir --index-url "$PIP_INDEX_URL" frida==17.2.17 \
    && python -m venv /opt/frida16 \
    && /opt/frida16/bin/pip install --no-cache-dir --index-url "$PIP_INDEX_URL" frida==16.7.19
COPY *.py *.js ./
COPY ui ./ui
COPY tests ./tests
COPY README.md LICENSE THIRD_PARTY_NOTICES.txt VALIDATION.txt ./
RUN mkdir -p /data /artifacts && python -m compileall -q /app
EXPOSE 7801
CMD ["python", "server.py"]
