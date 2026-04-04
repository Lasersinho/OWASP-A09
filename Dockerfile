# ============================================================================
# Dockerfile — OWASP A09 Lab: CWE-117 Log Injection / Log Forging
# Imagen base: python:3.11-alpine (ligera para laboratorios)
# ============================================================================

FROM python:3.11-alpine

# Metadatos del laboratorio
LABEL maintainer="Security Lab"
LABEL description="OWASP A09 — CWE-117: Log Injection / Log Forging Lab"
LABEL vulnerability="Log entries forging via unsanitized newline characters"

# Crear directorio de trabajo
WORKDIR /app

# Instalar dependencias
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Directorio de logs
RUN mkdir -p /app/logs && chmod 777 /app/logs

# Copiar el código del servidor y el frontend (por si no se usa volume)
COPY app.py ./
COPY frontend/ ./frontend/

# Exponer el puerto del servicio
EXPOSE 5000

# Comando de inicio
CMD ["python", "app.py"]
