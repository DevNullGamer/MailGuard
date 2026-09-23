FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN groupadd -r mailguard && useradd -r -g mailguard -d /app mailguard && mkdir -p /data && chown mailguard:mailguard /data
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=mailguard:mailguard app ./app
USER mailguard
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)"
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8080","--proxy-headers"]
