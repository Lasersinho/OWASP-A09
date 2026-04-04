/**
 * Frontend Interaction Script
 * Lab CWE-117 Log Injection
 */

document.addEventListener('DOMContentLoaded', () => {
    initCanvasParticles();
    initScrollAnimations();
    initExploitSimulation();
});

/* ==========================================================================
   1. Partículas Cyber (Canvas Background)
   ========================================================================== */
function initCanvasParticles() {
    const canvas = document.getElementById('networkCanvas');
    const ctx = canvas.getContext('2d');
    
    let w, h, particles = [];
    
    function resize() {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
    }
    
    window.addEventListener('resize', resize);
    resize();
    
    class Particle {
        constructor() {
            this.x = Math.random() * w;
            this.y = Math.random() * h;
            this.vx = (Math.random() - 0.5) * 0.5;
            this.vy = (Math.random() - 0.5) * 0.5;
            this.radius = Math.random() * 1.5 + 0.5;
        }
        
        move() {
            this.x += this.vx;
            this.y += this.vy;
            
            if (this.x < 0 || this.x > w) this.vx *= -1;
            if (this.y < 0 || this.y > h) this.vy *= -1;
        }
        
        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(0, 240, 255, 0.5)';
            ctx.fill();
        }
    }
    
    for (let i = 0; i < 70; i++) particles.push(new Particle());
    
    function animate() {
        ctx.clearRect(0, 0, w, h);
        
        particles.forEach(p => {
            p.move();
            p.draw();
        });
        
        // Connect lines
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dist = Math.hypot(particles[i].x - particles[j].x, particles[i].y - particles[j].y);
                if (dist < 120) {
                    ctx.beginPath();
                    ctx.strokeStyle = `rgba(0, 240, 255, ${0.15 - dist/800})`;
                    ctx.lineWidth = 0.5;
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.stroke();
                }
            }
        }
        requestAnimationFrame(animate);
    }
    animate();
}

/* ==========================================================================
   2. Scroll Animations (AOS Custom)
   ========================================================================== */
function initScrollAnimations() {
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, { threshold: 0.1 });
    
    document.querySelectorAll('.fade-in-up').forEach(el => observer.observe(el));
    
    // Check elements already in viewport on load
    setTimeout(() => {
        document.querySelectorAll('.fade-in-up').forEach(el => {
            const rect = el.getBoundingClientRect();
            if (rect.top < window.innerHeight) el.classList.add('visible');
        });
    }, 100);
}

/* ==========================================================================
   3. Simulated Exploit (Terminal UI & API calls)
   ========================================================================== */
function initExploitSimulation() {
    const runBtn = document.getElementById('runExploitBtn');
    const attackerConsole = document.getElementById('attackerConsole');
    const serverConsole = document.getElementById('serverConsole');
    let isRunning = false;
    
    // Función helper para agregar líneas al server log
    function addServerLog(type, msg, specialClass = '') {
        const line = document.createElement('div');
        line.className = `term-line ${type} ${specialClass}`;
        
        const pad = (num) => num.toString().padStart(2, '0');
        const now = new Date();
        const timestamp = `${now.getFullYear()}-${pad(now.getMonth()+1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
        
        line.textContent = `${timestamp} ${msg}`;
        serverConsole.appendChild(line);
        serverConsole.scrollTop = serverConsole.scrollHeight;
    }

    // Helper para consola de Hacker
    function addHackerLog(text, className) {
        const line = document.createElement('div');
        line.className = `term-line ${className}`;
        line.textContent = text;
        attackerConsole.appendChild(line);
        attackerConsole.scrollTop = attackerConsole.scrollHeight;
    }

    runBtn.addEventListener('click', async () => {
        if (isRunning) return;
        isRunning = true;
        runBtn.textContent = 'EXECUTING...';
        runBtn.style.opacity = '0.5';

        // 1. Mostrar intenciones del hacker
        document.querySelector('.waiting').style.display = 'none';
        addHackerLog('[*] Construyendo payload CR+LF...', 'hacker-text');
        
        // Payload visual para demostrar lo que se manda en vida real:
        const fakeTime = "2026-04-04 10:45:15";
        const injectedLine = `[INFO] LOGIN_SUCCESS user=admin ip=10.0.0.1 role=Administrator`;
        const payloadStr = `hacker\\r\\n${fakeTime} ${injectedLine}`;
        
        setTimeout(() => {
            addHackerLog(`[*] Payload: "${payloadStr}"`, 'hacker-text');
            addHackerLog('[*] Eviando POST a /api/login...', 'hacker-text');
        }, 800);

        // 2. Disparar API Real Local (Vulnerable)
        // Usaremos el payload original tal como lo pide el servidor vulnerable.
        setTimeout(async () => {
            try {
                // Hacemos el llamado a nuestro Backend Flask real
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: `hacker\n${fakeTime} ${injectedLine}`,
                        password: "fake"
                    })
                });
                
                // Mostrar resultados
                addHackerLog('[+] Respuesta del servidor (401 - Esperado para "hacker")', 'success-text');
                addHackerLog('[+] Inyección completada silenciósamente.', 'success-text');
                
                // 3. Simular visualmente en la ventana de Audit Logs
                // Esto pasa porque el servidor escribió directamene el string
                setTimeout(() => {
                    // Primer registro: El log real del intento "hacker"
                    addServerLog('log-info', `[INFO] LOGIN_ATTEMPT user=hacker`);
                    
                    // Segundo registro INYECTADO
                    setTimeout(() => {
                        // Lo renderizamos visualmente como ROJO para que el usuario se dé cuenta de la brecha
                        const line = document.createElement('div');
                        line.className = `term-line log-info log-injection`;
                        line.textContent = `${fakeTime} ${injectedLine}     <-- INYECTADO!`;
                        serverConsole.appendChild(line);
                        
                        // Tercer registro: El fallo real de credenciales del hacker (así funciona the codebase)
                        setTimeout(() => {
                            addServerLog('log-warn', `[WARNING] LOGIN_FAILED user=hacker ip=127.0.0.1 reason=invalid_credentials`);
                            serverConsole.scrollTop = serverConsole.scrollHeight;

                            // Reset
                            isRunning = false;
                            runBtn.textContent = 'RUN AGAIN';
                            runBtn.style.opacity = '1';
                        }, 400);

                    }, 100);

                }, 500);

            } catch (err) {
                addHackerLog('[-] Error contactando al Backend local. Verifica que Docker funciona.', 'error-text');
                isRunning = false;
                runBtn.textContent = 'RETRY';
            }
        }, 1800);
    });
}
