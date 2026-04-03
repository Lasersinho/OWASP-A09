// ============================================================================
// server.js — Servidor Vulnerable: OWASP A09 / CWE-778 (Insufficient Logging)
// ============================================================================
// Este servidor simula el fallo reportado en AWS Global Accelerator, donde
// endpoints "no productivos" (beta/internal) permitían la enumeración
// silenciosa de permisos al NO estar cubiertos por el sistema de auditoría
// (CloudTrail), mientras que los endpoints de producción sí registraban
// toda la actividad correctamente.
// ============================================================================

const express = require('express');
const app = express();
const PORT = 3000;

app.use(express.json());

// ============================================================================
// DATOS SIMULADOS — Usuarios, roles y permisos internos
// ============================================================================

const USERS = {
  'token-admin-001': {
    id: 1,
    username: 'admin',
    role: 'Administrator',
    permissions: [
      'iam:CreateUser',
      'iam:DeleteUser',
      'iam:AttachPolicy',
      'ec2:TerminateInstances',
      's3:DeleteBucket',
      'cloudtrail:StopLogging',     // ← Permiso crítico
      'globalaccelerator:FullAccess'
    ]
  },
  'token-dev-042': {
    id: 2,
    username: 'developer',
    role: 'Developer',
    permissions: [
      'ec2:DescribeInstances',
      's3:GetObject',
      's3:PutObject',
      'lambda:InvokeFunction'
    ]
  },
  'token-readonly-099': {
    id: 3,
    username: 'auditor',
    role: 'ReadOnly',
    permissions: [
      'ec2:DescribeInstances',
      's3:ListBucket',
      'cloudwatch:GetMetricData'
    ]
  }
};

const INTERNAL_ROLES = [
  { role: 'Administrator', level: 'CRITICAL', canEscalate: true },
  { role: 'Developer',     level: 'MEDIUM',   canEscalate: false },
  { role: 'ReadOnly',      level: 'LOW',      canEscalate: false },
  { role: 'ServiceAccount', level: 'HIGH',    canEscalate: true }
];

// ============================================================================
// MIDDLEWARE: cloudTrailLogger — Simula AWS CloudTrail
// ============================================================================
// Este middleware registra en consola (stdout) cada petición que lo atraviesa,
// simulando un log de auditoría. Captura: timestamp, IP, método, ruta y token.
//
// ⚠️  FALLA ARQUITECTÓNICA:
//     Este middleware SOLO se aplica a las rutas de "producción" (/api/v1/*).
//     Los endpoints beta e internos (/api/beta/*, /api/internal/*) fueron
//     montados SIN este middleware, lo que permite enumeración silenciosa.
// ============================================================================

function cloudTrailLogger(req, res, next) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    eventSource: 'globalaccelerator.amazonaws.com',
    eventName: `${req.method} ${req.path}`,
    sourceIPAddress: req.ip || req.connection.remoteAddress,
    userAgent: req.headers['user-agent'] || 'Unknown',
    userIdentity: req.headers['x-auth-token'] || 'anonymous',
    requestParameters: {
      method: req.method,
      path: req.originalUrl,
      query: req.query
    },
    responseElements: null,
    eventType: 'AwsApiCall',
    recipientAccountId: '123456789012'
  };

  // ─── Registro visible en los logs del contenedor ───
  console.log(`[CloudTrail] ${JSON.stringify(logEntry)}`);

  next();
}

// ============================================================================
// HELPER: Extraer usuario del token
// ============================================================================

function getUserFromToken(req) {
  const token = req.headers['x-auth-token'];
  if (!token) return null;
  return USERS[token] || null;
}

// ============================================================================
// RUTAS DE PRODUCCIÓN — /api/v1/*
// ============================================================================
// Estas rutas utilizan el middleware cloudTrailLogger.
// Toda petición queda registrada en los logs de auditoría (stdout).
// ============================================================================

const productionRouter = express.Router();

// ✅ Aplica el middleware de auditoría a TODAS las rutas de producción
productionRouter.use(cloudTrailLogger);

// GET /api/v1/users — Lista de usuarios (requiere autenticación)
productionRouter.get('/users', (req, res) => {
  const user = getUserFromToken(req);
  if (!user) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Valid x-auth-token header required'
    });
  }
  // Devuelve solo información pública
  const publicUsers = Object.values(USERS).map(u => ({
    id: u.id,
    username: u.username,
    role: u.role
  }));
  res.json({ status: 'ok', data: publicUsers });
});

// POST /api/v1/data — Enviar datos (requiere autenticación)
productionRouter.post('/data', (req, res) => {
  const user = getUserFromToken(req);
  if (!user) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Valid x-auth-token header required'
    });
  }
  res.json({
    status: 'ok',
    message: `Data received by ${user.username}`,
    recordId: `rec-${Date.now()}`
  });
});

// GET /api/v1/status — Estado del servicio
productionRouter.get('/status', (req, res) => {
  res.json({
    service: 'GlobalAccelerator',
    status: 'operational',
    region: 'us-east-1',
    timestamp: new Date().toISOString()
  });
});

app.use('/api/v1', productionRouter);

// ============================================================================
// RUTAS BETA / INTERNAS — /api/beta/* y /api/internal/*
// ============================================================================
// ⚠️  VULNERABILIDAD CWE-778: INSUFFICIENT LOGGING
//
// Estos routers NO utilizan el middleware cloudTrailLogger.
// Un atacante puede enumerar permisos, roles y configuraciones internas
// sin generar NINGÚN registro en los logs de auditoría.
//
// Esto replica el fallo real en AWS Global Accelerator donde ciertos
// endpoints "no productivos" no estaban instrumentados con CloudTrail,
// permitiendo reconocimiento silencioso.
// ============================================================================

const betaRouter = express.Router();
// ❌ NO se aplica cloudTrailLogger aquí — esta es la vulnerabilidad

// GET /api/beta/permissions/check — Enumerar permisos del usuario actual
betaRouter.get('/permissions/check', (req, res) => {
  const user = getUserFromToken(req);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  // ⚠️ Devuelve la lista COMPLETA de permisos sin registrar la consulta
  res.json({
    username: user.username,
    role: user.role,
    permissions: user.permissions,
    _warning: 'This endpoint is not monitored by CloudTrail'
  });
});

// GET /api/beta/permissions/enumerate — Verificar un permiso específico
betaRouter.get('/permissions/enumerate', (req, res) => {
  const user = getUserFromToken(req);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const permission = req.query.permission;
  if (!permission) {
    return res.status(400).json({ error: 'Missing ?permission= parameter' });
  }
  // ⚠️ Permite verificar permisos uno a uno sin dejar rastro
  const hasPermission = user.permissions.includes(permission);
  res.json({
    username: user.username,
    permission: permission,
    granted: hasPermission
  });
});

// GET /api/beta/account/info — Información de la cuenta
betaRouter.get('/account/info', (req, res) => {
  const user = getUserFromToken(req);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  res.json({
    accountId: '123456789012',
    user: user.username,
    role: user.role,
    mfaEnabled: false,
    lastLogin: '2026-04-01T10:30:00Z',
    sessionExpiry: '2026-04-02T10:30:00Z'
  });
});

app.use('/api/beta', betaRouter);

const internalRouter = express.Router();
// ❌ NO se aplica cloudTrailLogger aquí — esta es la vulnerabilidad

// GET /api/internal/roles — Lista todos los roles del sistema
internalRouter.get('/roles', (req, res) => {
  // ⚠️ Expone la jerarquía completa de roles sin auditoría
  res.json({
    roles: INTERNAL_ROLES,
    _note: 'Internal endpoint — no CloudTrail coverage'
  });
});

// GET /api/internal/config — Configuración interna del servicio
internalRouter.get('/config', (req, res) => {
  // ⚠️ Expone configuración sensible sin registrar
  res.json({
    service: 'GlobalAccelerator',
    loggingEnabled: true,
    loggingScope: ['/api/v1/*'],  // ← Revela qué rutas están monitoreadas
    unmonitoredPaths: ['/api/beta/*', '/api/internal/*'],
    debugMode: true,
    internalApiKey: 'sk-internal-4f8a2b1c-DO-NOT-EXPOSE'
  });
});

app.use('/api/internal', internalRouter);

// ============================================================================
// RUTA RAÍZ — Información del laboratorio
// ============================================================================

app.get('/', (req, res) => {
  res.json({
    lab: 'OWASP A09 — CWE-778: Insufficient Logging',
    description: 'Simulación del fallo en AWS Global Accelerator',
    endpoints: {
      production: {
        note: '✅ Monitoreados por CloudTrail',
        routes: [
          'GET  /api/v1/users',
          'POST /api/v1/data',
          'GET  /api/v1/status'
        ]
      },
      beta: {
        note: '❌ NO monitoreados — Vulnerables a enumeración silenciosa',
        routes: [
          'GET /api/beta/permissions/check',
          'GET /api/beta/permissions/enumerate?permission=<perm>',
          'GET /api/beta/account/info'
        ]
      },
      internal: {
        note: '❌ NO monitoreados — Exponen configuración sensible',
        routes: [
          'GET /api/internal/roles',
          'GET /api/internal/config'
        ]
      }
    },
    tokens: {
      admin: 'token-admin-001',
      developer: 'token-dev-042',
      auditor: 'token-readonly-099'
    }
  });
});

// ============================================================================
// INICIO DEL SERVIDOR
// ============================================================================

app.listen(PORT, '0.0.0.0', () => {
  console.log('='.repeat(70));
  console.log(' OWASP A09 Lab — CWE-778: Insufficient Logging');
  console.log(' Simulación: AWS Global Accelerator Silent Enumeration');
  console.log(` Servidor escuchando en http://0.0.0.0:${PORT}`);
  console.log('='.repeat(70));
  console.log('');
  console.log(' [INFO] CloudTrail habilitado para: /api/v1/*');
  console.log(' [WARN] CloudTrail NO cubre: /api/beta/*, /api/internal/*');
  console.log('');
});
