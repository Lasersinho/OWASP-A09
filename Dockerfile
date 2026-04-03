# ============================================================================
# Dockerfile — OWASP A09 Lab: CWE-778 Insufficient Logging
# Imagen base: node:18-alpine (ligera y segura para laboratorios)
# ============================================================================

FROM node:18-alpine

# Metadatos del laboratorio
LABEL maintainer="Security Lab"
LABEL description="OWASP A09 — CWE-778: Insufficient Logging Lab"
LABEL vulnerability="Silent permission enumeration via unmonitored endpoints"

# Crear directorio de trabajo
WORKDIR /app

# Copiar definición de dependencias e instalar
COPY package.json ./
RUN npm install --production

# Copiar código del servidor
COPY server.js ./

# Exponer el puerto del servicio
EXPOSE 3000

# Usuario no-root para buenas prácticas (aunque es un lab vulnerable)
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Comando de inicio
CMD ["node", "server.js"]
