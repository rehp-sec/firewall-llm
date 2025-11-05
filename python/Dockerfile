FROM python:3.10-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=America/Santiago

# Paquetes base
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        supervisor \
        curl \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

# Pip y dependencias (instalamos 'pyicap' original)
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir "fastapi[all]" uvicorn pyicap brotli

# --- EL PARCHE CORRECTO (para la línea 266) ---
# Arregla el bug "TypeError: can't concat str to bytes"
RUN PYICAP_FILE="$(python -c 'import inspect, pyicap; print(inspect.getfile(pyicap))')" && \
    echo "[build] pyicap file at: $PYICAP_FILE" && \
    sed -i "s/b' ' + message/b' ' + (message if isinstance(message, bytes) else str(message).encode('utf-8'))/g" "$PYICAP_FILE"

WORKDIR /app
COPY . .

EXPOSE 1344 8081
CMD ["/usr/bin/supervisord", "-c", "/app/supervisord_python.conf"]
