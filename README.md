# 🔒 OWASP A09 — CWE-778: Insufficient Logging

## Laboratorio "Vulnerable by Design"

### Simulación: Enumeración Silenciosa de Permisos en AWS Global Accelerator

---

## 📖 Descripción del Escenario

Este laboratorio replica un fallo de seguridad real reportado en **AWS Global Accelerator**, donde ciertos endpoints "no productivos" (beta/internos) permitían la **enumeración silenciosa de permisos** al no estar cubiertos por el sistema de auditoría **AWS CloudTrail**.

### ¿Qué es CWE-778?

**CWE-778: Insufficient Logging** describe una debilidad en la que un sistema de software no registra eventos de seguridad críticos o los registra con información insuficiente. Esto permite que un atacante realice actividades maliciosas **sin ser detectado**.

Según OWASP, las **Fallas en el Registro y Monitoreo de Seguridad (A09:2021)** ocurren cuando:

- Eventos auditables (como inicios de sesión, transacciones y actividades sensibles) no se registran.
- Los logs no se monitorean en busca de actividad sospechosa.
- Los registros solo se almacenan localmente.
- No existe un proceso de respuesta a incidentes.

### El Fallo en AWS Global Accelerator

En el escenario real, un investigador descubrió que ciertos endpoints de la API de AWS Global Accelerator **no generaban eventos en CloudTrail**. Esto significaba que un atacante podía:

1. **Descubrir** endpoints no monitoreados.
2. **Enumerar permisos** de cuentas IAM consultando repetidamente estos endpoints.
3. **Mapear la superficie de ataque** (roles, privilegios, configuración interna).
4. **Realizar todo lo anterior sin generar NINGÚN registro de auditoría**.

---

## 🏗️ Arquitectura del Laboratorio

```
┌──────────────────────────────────────────────────────────────┐
│                    Servidor Express.js                        │
│                                                              │
│  ┌─────────────────────┐    ┌──────────────────────────┐    │
│  │   /api/v1/* (PROD)  │    │  /api/beta/* (BETA)      │    │
│  │                     │    │  /api/internal/* (INT)    │    │
│  │  ┌───────────────┐  │    │                          │    │
│  │  │ cloudTrail    │  │    │  ❌ SIN middleware de     │    │
│  │  │ Logger        │  │    │     auditoría             │    │
│  │  │ (middleware)  │  │    │                          │    │
│  │  └──────┬────────┘  │    │  → Enumeración silenciosa│    │
│  │         │           │    │  → Sin rastro en logs    │    │
│  │    📝 LOG → stdout  │    │  → 👻 Invisible           │    │
│  └─────────────────────┘    └──────────────────────────┘    │
│                                                              │
└──────────────────────────────────┬───────────────────────────┘
                                   │
                              Puerto 3000
                                   │
                          ┌────────┴────────┐
                          │   Docker Host   │
                          └─────────────────┘
```

### Endpoints Disponibles

| Ruta | Tipo | CloudTrail | Descripción |
|------|------|------------|-------------|
| `GET /api/v1/users` | Producción | ✅ Sí | Lista usuarios (requiere token) |
| `POST /api/v1/data` | Producción | ✅ Sí | Enviar datos (requiere token) |
| `GET /api/v1/status` | Producción | ✅ Sí | Estado del servicio |
| `GET /api/beta/permissions/check` | Beta | ❌ No | Lista TODOS los permisos del usuario |
| `GET /api/beta/permissions/enumerate` | Beta | ❌ No | Verifica un permiso específico |
| `GET /api/beta/account/info` | Beta | ❌ No | Información de la cuenta |
| `GET /api/internal/roles` | Interno | ❌ No | Lista roles del sistema |
| `GET /api/internal/config` | Interno | ❌ No | Configuración interna sensible |

### Tokens de Autenticación

| Usuario | Token | Rol |
|---------|-------|-----|
| admin | `token-admin-001` | Administrator |
| developer | `token-dev-042` | Developer |
| auditor | `token-readonly-099` | ReadOnly |

---

## 🚀 Instrucciones de Despliegue

### Prerrequisitos

- [Docker](https://docs.docker.com/get-docker/) instalado
- [Docker Compose](https://docs.docker.com/compose/install/) instalado
- [Python 3](https://www.python.org/downloads/) con `requests` (`pip install requests`)

### 1. Clonar el repositorio

```bash
git clone <url-del-repositorio>
cd A09
```

### 2. Levantar el laboratorio

```bash
docker-compose up -d
```

Verificar que está corriendo:

```bash
docker ps
# Deberías ver: owasp-a09-cwe778-lab en estado "Up"
```

### 3. Verificar el servicio

```bash
curl http://localhost:3000/
# Debería devolver la información del laboratorio en JSON
```

---

## 💀 Instrucciones de Explotación

### Paso 1: Ejecutar el script de reconocimiento

```bash
pip install requests
python recon_script.py
```

El script ejecutará **3 fases**:

1. **Fase 1** — Peticiones a endpoints de producción (3 peticiones → registradas).
2. **Fase 2** — Reconocimiento silencioso de configuración, roles y permisos.
3. **Fase 3** — Enumeración masiva (brute force) de 20 permisos AWS contra el token admin.

### Paso 2: Revisar los logs del contenedor

```bash
docker logs owasp-a09-cwe778-lab
```

### Paso 3: Comparar y analizar

**Lo que verás en los logs:**

```
[CloudTrail] {"timestamp":"...","eventName":"GET /status","sourceIPAddress":"::ffff:172.17.0.1",...}
[CloudTrail] {"timestamp":"...","eventName":"GET /users","userIdentity":"token-dev-042",...}
[CloudTrail] {"timestamp":"...","eventName":"POST /data","userIdentity":"token-dev-042",...}
```

**Lo que NO verás en los logs:**

- ❌ Las ~5 peticiones de reconocimiento a `/api/beta/*`
- ❌ Las ~2 peticiones a `/api/internal/*`
- ❌ Las 20 peticiones de enumeración masiva de permisos

**Resultado:** El atacante extrajo configuración interna, roles del sistema, API keys, y los permisos completos de 3 usuarios — realizando ~30 peticiones — sin generar **ni un solo registro de auditoría**.

---

## 🛡️ Remediación

### ¿Cómo se corrige esta vulnerabilidad?

La solución es aplicar el middleware de auditoría **a nivel de la aplicación completa**, no solo a rutas específicas:

```javascript
// ❌ VULNERABLE — Middleware solo en producción
const productionRouter = express.Router();
productionRouter.use(cloudTrailLogger);
app.use('/api/v1', productionRouter);

// Los routers beta/internal NO tienen el middleware
app.use('/api/beta', betaRouter);
app.use('/api/internal', internalRouter);
```

```javascript
// ✅ SEGURO — Middleware global ANTES de montar cualquier ruta
app.use(cloudTrailLogger);  // ← Se aplica a TODAS las rutas

app.use('/api/v1', productionRouter);
app.use('/api/beta', betaRouter);
app.use('/api/internal', internalRouter);
```

### Mejores Prácticas

1. **Logging global**: Aplicar middleware de auditoría a nivel de aplicación, no de router.
2. **Cobertura completa**: Verificar que TODOS los endpoints (incluyendo beta, staging, internos) estén cubiertos por el sistema de logging.
3. **Alertas**: Configurar alertas para patrones de enumeración (múltiples peticiones a endpoints de permisos).
4. **Revisión periódica**: Auditar regularmente qué rutas están cubiertas por el sistema de monitoreo.
5. **Principio de defensa en profundidad**: No confiar en una sola capa de logging.

---

## 📁 Estructura del Repositorio

```
A09/
├── server.js              # Servidor Express.js vulnerable
├── package.json           # Dependencias del proyecto (express)
├── Dockerfile             # Imagen Docker (node:18-alpine)
├── docker-compose.yml     # Orquestación del contenedor
├── recon_script.py        # Script de explotación en Python 3
└── README.md              # Este documento
```

---

## 📚 Referencias

- [OWASP Top 10 — A09:2021 Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
- [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
- [AWS CloudTrail Documentation](https://docs.aws.amazon.com/cloudtrail/)
- [AWS Global Accelerator — Security Considerations](https://docs.aws.amazon.com/global-accelerator/latest/dg/security.html)

---

## ⚠️ Disclaimer

Este laboratorio está diseñado **exclusivamente con fines educativos**. El uso de estas técnicas contra sistemas sin autorización es ilegal. Úsalo solo en entornos controlados y con permiso explícito.
