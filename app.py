#!/usr/bin/env python3
# ============================================================================
# app.py — Servidor Vulnerable: OWASP A09 / CWE-117 (Log Injection / Forging)
# ============================================================================
#
#  ██╗      ██████╗  ██████╗     ██╗███╗   ██╗     ██╗███████╗ ██████╗████████╗
#  ██║     ██╔═══██╗██╔════╝     ██║████╗  ██║     ██║██╔════╝██╔════╝╚══██╔══╝
#  ██║     ██║   ██║██║  ███╗    ██║██╔██╗ ██║     ██║█████╗  ██║        ██║
#  ██║     ██║   ██║██║   ██║    ██║██║╚██╗██║██   ██║██╔══╝  ██║        ██║
#  ███████╗╚██████╔╝╚██████╔╝    ██║██║ ╚████║╚█████╔╝███████╗╚██████╗   ██║
#  ╚══════╝ ╚═════╝  ╚═════╝     ╚═╝╚═╝  ╚═══╝ ╚════╝╚══════╝ ╚═════╝   ╚═╝
#
# Este servidor demuestra la vulnerabilidad CWE-117: Improper Output
# Neutralization for Logs (Log Injection / Log Forging).
#
# VULNERABILIDAD PRINCIPAL:
#   El servidor escribe datos proporcionados por el usuario directamente en
#   los archivos de log SIN sanitizar caracteres de control como \n (nueva
#   línea) y \r (retorno de carro). Esto permite a un atacante:
#
#   1. FORGE LOG ENTRIES: Inyectar líneas de log falsas que parecen legítimas.
#   2. SIMULATE ADMIN ACTIVITY: Crear entradas falsas de login de admin.
#   3. HIDE ATTACKS: Inyectar cientos de líneas basura para ocultar actividad.
#   4. CORRUPT AUDITS: Falsificar registros de auditoría críticos.
#
# ============================================================================

import os
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory

# ============================================================================
# CONFIGURACIÓN DE LOGGING — Archivo de log centralizado
# ============================================================================
# Se configura un archivo de log que simula un sistema de auditoría real.
# Este archivo es el OBJETIVO del ataque de Log Injection.
# ============================================================================

LOG_FILE = '/app/logs/server_audit.log'
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Configuración del logger principal
logger = logging.getLogger('audit')
logger.setLevel(logging.INFO)

# Handler para archivo de log
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.INFO)

# Handler para consola (stdout — visible en docker logs)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Formato de log estilo producción
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(message)s'
formatter = logging.Formatter(LOG_FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)


# ============================================================================
# FLASK APP — Inicialización
# ============================================================================

app = Flask(__name__, static_folder='frontend', static_url_path='')


# ============================================================================
# DATOS SIMULADOS — Usuarios y credenciales del sistema
# ============================================================================

USERS_DB = {
    'admin': {
        'password': 'S3cur3P@ss!',
        'role': 'Administrator',
        'full_name': 'Carlos Rivera',
        'email': 'admin@empresa-corp.local'
    },
    'auditor': {
        'password': 'AuditPass99',
        'role': 'Security Auditor',
        'full_name': 'Maria García',
        'email': 'auditor@empresa-corp.local'
    },
    'developer': {
        'password': 'DevPass123',
        'role': 'Developer',
        'full_name': 'Juan Pérez',
        'email': 'dev@empresa-corp.local'
    }
}

AUDIT_EVENTS = []  # Cola de eventos de auditoría en memoria


# ============================================================================
# FUNCIÓN VULNERABLE — write_log()
# ============================================================================
# ⚠️  CWE-117: IMPROPER OUTPUT NEUTRALIZATION FOR LOGS
#
# Esta función escribe datos proporcionados por el usuario DIRECTAMENTE
# en el archivo de log sin sanitizar caracteres de control.
#
# El problema: si el usuario incluye \n (nueva línea) en su input,
# el logger interpretará esto como saltos de línea REALES, permitiendo
# que el atacante "inyecte" líneas de log completamente fabricadas.
#
# Ejemplo de ataque:
#   username = "hacker\n2026-04-04 10:00:00 [INFO] LOGIN_SUCCESS user=admin ip=10.0.0.1"
#
#   Esto genera DOS entradas en el log:
#     2026-04-04 10:00:01 [INFO] LOGIN_ATTEMPT user=hacker ip=192.168.1.100
#     2026-04-04 10:00:00 [INFO] LOGIN_SUCCESS user=admin ip=10.0.0.1
#
#   La segunda línea es COMPLETAMENTE FALSA pero parece legítima.
# ============================================================================

def write_log(level, message):
    """
    ⚠️ VULNERABLE: Escribe directamente al log sin sanitizar.
    Los caracteres \\n y \\r en 'message' crearán nuevas líneas en el log,
    permitiendo la inyección de entradas falsas.
    """
    # ─── AQUÍ ESTÁ LA VULNERABILIDAD ───
    # El mensaje se pasa directamente al logger sin filtrar \n, \r, etc.
    # Un atacante puede inyectar cualquier contenido en el registro.
    if level == 'INFO':
        logger.info(message)
    elif level == 'WARNING':
        logger.warning(message)
    elif level == 'ERROR':
        logger.error(message)
    elif level == 'CRITICAL':
        logger.critical(message)


def write_log_safe(level, message):
    """
    ✅ VERSIÓN SEGURA: Sanitiza el mensaje antes de escribirlo.
    Remueve caracteres de control que podrían alterar la estructura del log.
    """
    # ─── MITIGACIÓN CWE-117 ───
    # Reemplaza caracteres de nueva línea y retorno de carro
    sanitized = message.replace('\n', '\\n').replace('\r', '\\r')
    # Elimina otros caracteres de control ASCII (0x00 - 0x1F excepto tab)
    sanitized = ''.join(
        char if (ord(char) >= 32 or char == '\t') else f'\\x{ord(char):02x}'
        for char in sanitized
    )
    if level == 'INFO':
        logger.info(sanitized)
    elif level == 'WARNING':
        logger.warning(sanitized)
    elif level == 'ERROR':
        logger.error(sanitized)
    elif level == 'CRITICAL':
        logger.critical(sanitized)


# ============================================================================
# RUTA RAÍZ — Servir la interfaz web estática
# ============================================================================

@app.route('/')
def serve_frontend():
    """Sirve el archivo index.html de la carpeta frontend."""
    return send_from_directory(app.static_folder, 'index.html')


# ============================================================================
# ENDPOINT 1: /api/login — Autenticación (VULNERABLE a Log Injection)
# ============================================================================
# ⚠️  CWE-117: El campo 'username' se registra directamente en los logs.
#     Un atacante puede inyectar \n seguido de una entrada de log falsa
#     en el campo username para fabricar registros de auditoría.
# ============================================================================

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')
    ip = request.remote_addr

    # ⚠️ VULNERABLE: El username se escribe DIRECTAMENTE en el log
    #    sin sanitizar caracteres de nueva línea (\n, \r)
    write_log('INFO', f'LOGIN_ATTEMPT user={username} ip={ip} status=pending')

    # Verificar credenciales
    user = USERS_DB.get(username)
    if user and user['password'] == password:
        write_log('INFO', f'LOGIN_SUCCESS user={username} ip={ip} role={user["role"]}')
        return jsonify({
            'status': 'success',
            'message': f'Bienvenido, {user["full_name"]}',
            'user': {
                'username': username,
                'role': user['role'],
                'email': user['email']
            }
        })
    else:
        write_log('WARNING', f'LOGIN_FAILED user={username} ip={ip} reason=invalid_credentials')
        return jsonify({
            'status': 'error',
            'message': 'Credenciales inválidas'
        }), 401


# ============================================================================
# ENDPOINT 2: /api/transfer — Transferencia financiera (VULNERABLE)
# ============================================================================
# ⚠️  CWE-117: El campo 'description' se registra sin sanitizar.
#     Un atacante puede inyectar entradas de log falsas que simulen
#     aprobaciones de auditoría o transacciones legítimas.
# ============================================================================

@app.route('/api/transfer', methods=['POST'])
def transfer():
    data = request.get_json(force=True, silent=True) or {}
    from_account = data.get('from', 'unknown')
    to_account = data.get('to', 'unknown')
    amount = data.get('amount', 0)
    description = data.get('description', '')  # ⚠️ Campo inyectable
    ip = request.remote_addr

    # ⚠️ VULNERABLE: La descripción se escribe directamente al log
    write_log('INFO',
        f'TRANSFER_REQUEST from={from_account} to={to_account} '
        f'amount=${amount} description="{description}" ip={ip}'
    )

    # Simular procesamiento
    if not from_account or not to_account or not amount:
        write_log('ERROR', f'TRANSFER_FAILED reason=missing_fields ip={ip}')
        return jsonify({'status': 'error', 'message': 'Campos requeridos faltantes'}), 400

    write_log('INFO',
        f'TRANSFER_COMPLETE txid=TXN-{datetime.now().strftime("%Y%m%d%H%M%S")} '
        f'from={from_account} to={to_account} amount=${amount}'
    )

    return jsonify({
        'status': 'success',
        'message': 'Transferencia procesada',
        'transaction_id': f'TXN-{datetime.now().strftime("%Y%m%d%H%M%S")}'
    })


# ============================================================================
# ENDPOINT 3: /api/search — Búsqueda (VULNERABLE)
# ============================================================================
# ⚠️  CWE-117: El término de búsqueda se registra sin sanitizar.
# ============================================================================

@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('q', '')  # ⚠️ Parámetro inyectable
    ip = request.remote_addr

    # ⚠️ VULNERABLE: El query se escribe directamente al log
    write_log('INFO', f'SEARCH_QUERY query="{query}" ip={ip}')

    return jsonify({
        'status': 'success',
        'query': query,
        'results': [],
        'message': 'Búsqueda completada (sin resultados simulados)'
    })


# ============================================================================
# ENDPOINT 4: /api/audit — Registrar evento de auditoría (VULNERABLE)
# ============================================================================
# ⚠️  CWE-117: El campo 'action' se escribe directamente a los logs.
#     Un atacante puede fabricar eventos de auditoría completamente falsos.
# ============================================================================

@app.route('/api/audit', methods=['POST'])
def audit_event():
    data = request.get_json(force=True, silent=True) or {}
    action = data.get('action', '')  # ⚠️ Campo inyectable
    user = data.get('user', 'anonymous')
    resource = data.get('resource', 'unknown')
    ip = request.remote_addr

    # ⚠️ VULNERABLE: Se escribe directamente al log
    write_log('INFO', f'AUDIT_EVENT action={action} user={user} resource={resource} ip={ip}')

    # Almacenar en cola en memoria
    event = {
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'user': user,
        'resource': resource,
        'ip': ip
    }
    AUDIT_EVENTS.append(event)

    return jsonify({'status': 'recorded', 'event': event})


# ============================================================================
# ENDPOINT 5: /api/logs — Ver logs del servidor (para la UI)
# ============================================================================
# Este endpoint permite a la interfaz web mostrar los logs en tiempo real.
# ============================================================================

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Lee y devuelve las últimas N líneas del archivo de log."""
    lines_count = request.args.get('lines', 50, type=int)
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()
        # Devolver las últimas N líneas
        recent_lines = all_lines[-lines_count:] if len(all_lines) > lines_count else all_lines
        return jsonify({
            'status': 'success',
            'total_lines': len(all_lines),
            'returned_lines': len(recent_lines),
            'logs': [line.strip() for line in recent_lines if line.strip()]
        })
    except FileNotFoundError:
        return jsonify({'status': 'success', 'total_lines': 0, 'logs': []})


# ============================================================================
# ENDPOINT 6: /api/logs/clear — Limpiar logs (para reiniciar demos)
# ============================================================================

@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    """Limpia el archivo de log para reiniciar la demostración."""
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write('')
        write_log('INFO', 'SYSTEM: Log file cleared by administrator')
        return jsonify({'status': 'success', 'message': 'Logs cleared'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============================================================================
# ENDPOINT 7: /api/info — Información del laboratorio
# ============================================================================

@app.route('/api/info', methods=['GET'])
def lab_info():
    return jsonify({
        'lab': 'OWASP A09:2021 — CWE-117: Log Injection / Log Forging',
        'version': '1.0.0',
        'vulnerability': 'Improper Output Neutralization for Logs',
        'description': (
            'Este servidor escribe datos del usuario directamente en los logs '
            'sin sanitizar caracteres de control (\\n, \\r). Un atacante puede '
            'inyectar entradas de log falsas para falsificar auditorías, '
            'simular actividad de admin, u ocultar ataques reales.'
        ),
        'endpoints': {
            'POST /api/login': 'Autenticación — Campo username inyectable',
            'POST /api/transfer': 'Transferencia — Campo description inyectable',
            'GET  /api/search?q=': 'Búsqueda — Parámetro q inyectable',
            'POST /api/audit': 'Auditoría — Campo action inyectable',
            'GET  /api/logs': 'Ver logs del servidor',
            'POST /api/logs/clear': 'Limpiar logs'
        }
    })


# ============================================================================
# INICIO DEL SERVIDOR
# ============================================================================

if __name__ == '__main__':
    print('=' * 72)
    print('  ⚠️  OWASP A09:2021 — CWE-117: Log Injection / Log Forging Lab')
    print('  ⚠️  Este servidor es INTENCIONALMENTE VULNERABLE')
    print('  ⚠️  Solo para uso educativo en entornos controlados')
    print('=' * 72)
    print()
    write_log('INFO', 'SERVER_START service=LogInjectionLab port=5000')
    write_log('INFO', 'SYSTEM: Audit logging initialized — file: /app/logs/server_audit.log')
    write_log('WARNING', 'SYSTEM: Input sanitization DISABLED on user-facing endpoints')
    print()

    app.run(host='0.0.0.0', port=5000, debug=False)
