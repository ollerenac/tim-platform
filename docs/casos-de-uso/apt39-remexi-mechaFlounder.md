---
layout: page
title: "Caso de Uso: APT39"
description: "Cómo navegar desde un malware hasta su actor, explorar el arsenal completo y comparar TTPs entre dos implantes del mismo grupo iraní APT39."
---

**Objetivo:** Navegar OpenCTI desde un malware conocido hasta su actor amenaza, explorar el arsenal completo del grupo y comparar las técnicas ATT&CK entre dos implantes del mismo actor.

**Actor:** APT39 (alias: ITG07, Chafer, Remix Kitten) — grupo de espionaje iraní atribuido al MOIS  
**Malwares cubiertos:** Remexi (backdoor compilado) y MechaFlounder (RAT en Python)  
**Tiempo estimado:** 30–45 minutos

---

## Contexto previo

APT39 es un grupo de amenaza persistente avanzada (APT) de origen iraní, atribuido al Ministerio de Inteligencia y Seguridad (MOIS). Sus objetivos principales son organizaciones de telecomunicaciones, turismo y académicas. Se distingue por mantener dos tipos de implantes en paralelo: herramientas compiladas maduras (Remexi) y RATs ágiles en Python (MechaFlounder), lo que le permite adaptarse según el entorno de la víctima.

---

## Paso 1 — Acceder a OpenCTI

1. Abrir `http://localhost:8080` en el navegador.
2. Iniciar sesión con las credenciales de administrador (ver `.env` → `OPENCTI_ADMIN_EMAIL` / `OPENCTI_ADMIN_PASSWORD`).
3. El dashboard principal muestra el resumen de la plataforma.

---

## Paso 2 — Explorar Remexi

### 2.1 Navegar al malware

1. En el menú lateral izquierdo, seleccionar **Arsenal → Malware**.
2. Buscar `Remexi` en el campo de búsqueda superior o usar la búsqueda global.
3. Hacer clic en **Remexi** para abrir su ficha.

### 2.2 Pestaña Overview

La vista general muestra:

| Campo | Valor |
|-------|-------|
| Tipo | Backdoor / Troyano de acceso remoto |
| Es familia | Sí |
| Autor | The MITRE Corporation |
| Fuente | Conector MITRE ATT&CK (S0375) |
| Estado de procesamiento | Desactivado (ciclo de vida de detección no configurado) |

> **Nota:** El campo *Processing status* (Desactivado) y el *Detection toggle* son independientes. El primero refleja el ciclo de vida del indicador en el sistema; el segundo es un campo de usuario para marcar si el IOC tiene detección activa. Que ambos estén desactivados en datos MITRE es normal: MITRE no publica IOCs, solo comportamiento.

### 2.3 Pestaña Knowledge — Línea de tiempo de TTPs

1. Hacer clic en la pestaña **Knowledge**.
2. Seleccionar **Attack patterns (16)** en el menú lateral derecho.
3. En la barra de vistas superiores, elegir **TIMELINE** para ver las técnicas en orden cronológico.

Remexi usa **16 técnicas ATT&CK** que cubren todo el ciclo de vida del ataque:

| TTP | Nombre | Descripción operacional |
|-----|--------|------------------------|
| T1547.001 | Registry Run Keys / Startup Folder | Persistencia en arranque mediante claves de registro |
| T1059.003 | Windows Command Shell | Ejecución de comandos vía `cmd.exe` |
| T1056.001 | Keylogging | Captura de pulsaciones de teclado |
| T1115 | Clipboard Data | Robo de contenido del portapapeles |
| T1113 | Screen Capture | Capturas de pantalla periódicas |
| T1005 | Data from Local System | Recolección de archivos locales |
| T1041 | Exfiltration Over C2 Channel | Exfiltración por el mismo canal C2 |
| T1071.001 | Web Protocols | C2 sobre HTTP/S |
| T1132 | Data Encoding | Codificación de tráfico C2 |
| T1027 | Obfuscated Files or Information | Ofuscación de archivos y código |
| T1057 | Process Discovery | Enumeración de procesos en ejecución |
| T1082 | System Information Discovery | Obtención de info del sistema operativo |
| T1033 | System Owner/User Discovery | Identificación del usuario actual |
| T1083 | File and Directory Discovery | Enumeración del sistema de archivos |
| T1543.003 | Windows Service | Persistencia mediante servicios de Windows |
| T1105 | Ingress Tool Transfer | Descarga de herramientas adicionales |

> **Clave de análisis:** Remexi cubre las fases de **persistencia**, **recolección** (keylogging, portapapeles, pantalla) y **exfiltración** de forma completa. Es un implante maduro diseñado para operaciones de largo plazo sin ser detectado.

---

## Paso 3 — Pivotar a APT39 desde Remexi

### 3.1 Navegar al actor

Desde la ficha de Remexi:

1. Hacer clic en la pestaña **Knowledge**.
2. En el menú lateral derecho, bajo **Threats**, seleccionar **Intrusion sets (1)**.
3. Hacer clic en **APT39** para abrir la ficha del actor.

Alternativamente, desde la búsqueda global escribir `APT39` y seleccionar el resultado de tipo *Intrusion Set*.

---

## Paso 4 — Explorar APT39

### 4.1 Overview del actor

| Campo | Valor |
|-------|-------|
| STIX ID | `intrusion-set--6a7389f4-b0a2-556e-aa68-5089046ca569` |
| Alias | ITG07, Chafer, Remix Kitten |
| Atribución | Ministerio de Inteligencia y Seguridad de Irán (MOIS) |
| Objetivos principales | Telecomunicaciones, turismo, sector académico |
| Autor | The MITRE Corporation |

### 4.2 Modelo Diamond (Knowledge → Diamond)

La vista Diamond organiza el actor en cuatro vértices:

```
          [Adversario]
         APT39 / MOIS

[Capacidades]          [Infraestructura]
4 malwares             Sin IOCs
53 TTPs ATT&CK         (MITRE no publica IPs/dominios)

          [Víctimas]
     Telecomunicaciones
     Turismo / Académico
```

> **Por qué Infraestructura aparece vacía:** Los datos de MITRE ATT&CK describen *comportamiento* (TTPs), no *infraestructura* (IPs, dominios, hashes). Para ver infraestructura real de APT39 se necesitarían feeds de inteligencia operacional como Mandiant, CrowdStrike o OSINT de campañas documentadas.

### 4.3 Arsenal — Los 4 malwares de APT39

Desde **Knowledge → Arsenal → Malware (4)**:

| Malware | Tipo | Característica principal |
|---------|------|--------------------------|
| **ASPXSpy** | Web Shell | Acceso persistente en servidores web IIS |
| **Cadelspy** | Keylogger / Spyware | Captura teclado + pantalla, orientado a espionaje |
| **Remexi** | Backdoor | Implante C compilado, operaciones de largo plazo |
| **MechaFlounder** | RAT Python | Acceso remoto ágil, usa fragmentos de código público |

> **Diferencia clave entre Remexi y MechaFlounder:** Remexi es un implante compilado y maduro (≥2015), diseñado para persistir años sin ser detectado. MechaFlounder (documentado en 2019 por Unit 42 de Palo Alto) es un RAT en Python más ligero que combina código propio con fragmentos de repositorios públicos. APT39 los usa en paralelo: Remexi para operaciones profundas, MechaFlounder para acceso rápido o cuando Python ya está disponible en el host.

> **Herramienta adicional — NBTscan:** En búsquedas relacionadas con APT39 también aparece *NBTscan* (tipo: Tool, no Malware). Es un escáner de red legítimo que APT39 utiliza para reconocimiento interno (T1046 — Network Service Discovery). OpenCTI diferencia *Malware* (malicioso por naturaleza) de *Tool* (legítimo pero weaponizado).

---

## Paso 5 — Explorar MechaFlounder

### 5.1 Navegar al malware

Desde el arsenal de APT39, hacer clic en **MechaFlounder**, o buscar directamente desde la búsqueda global.

### 5.2 Overview

| Campo | Valor |
|-------|-------|
| STIX ID | `malware--f205180e-53b8-583c-aee7-ce328164970d` |
| Es familia | Sí |
| Lenguaje | Python |
| Fuente | Unit 42 — Palo Alto Networks (marzo 2019) |
| Fecha de creación original | 27 de mayo de 2020 |

**Descripción original (MITRE):**
> *"MechaFlounder is a python-based remote access tool (RAT) that has been used by APT39. The payload uses a combination of actor developed code and code snippets freely available online in development communities."*

> **Por qué esto importa para detección:** Que MechaFlounder use fragmentos de código público complica la atribución por similitud de código. No se puede asumir "mismo actor" solo por código compartido. La detección conductual (T1059.006 Python ejecutando conexiones C2) es más fiable que la detección por firma.

### 5.3 TTPs de MechaFlounder (8 técnicas)

Desde **Knowledge → TIMELINE**:

| TTP | Nombre | Descripción operacional |
|-----|--------|------------------------|
| T1105 | Ingress Tool Transfer | Descarga/sube payloads adicionales tras acceso inicial |
| T1059.006 | Python | El malware ES un script Python — su mecanismo de ejecución |
| T1059.003 | Windows Command Shell | Puede lanzar `cmd.exe` para ejecutar comandos del sistema |
| T1071.001 | Web Protocols | C2 sobre HTTP — se mezcla con tráfico web legítimo |
| T1132.001 | Standard Encoding | Codifica datos en base16 para ofuscar el tráfico C2 |
| T1033 | System Owner/User Discovery | Identifica el nombre de usuario del host comprometido |
| T1036.005 | Match Legitimate Resource Name | Se disfraza con nombre de archivo legítimo |
| T1041 | Exfiltration Over C2 Channel | Exfiltra datos robados por el mismo canal HTTP del C2 |

---

## Comparativa: Remexi vs MechaFlounder

| Dimensión | Remexi | MechaFlounder |
|-----------|--------|---------------|
| Lenguaje | C/C++ compilado | Python interpretado |
| TTPs | 16 técnicas | 8 técnicas |
| Persistencia | Sí (registro + servicios) | No documentada |
| Recolección | Keylogging, pantalla, portapapeles, archivos | No — solo exfiltración básica |
| C2 | HTTP/S con codificación propia | HTTP con base16 |
| Dependencia | Ninguna (binario standalone) | Requiere Python en el host |
| Primera documentación | ~2015 | Marzo 2019 (Unit 42) |
| Caso de uso APT39 | Implantación profunda, largo plazo | Acceso rápido, entornos con Python |

---

## Conceptos clave aprendidos

**Modelo Diamond:** Marco analítico que relaciona Adversario ↔ Capacidades ↔ Infraestructura ↔ Víctimas. Útil para entender qué *falta* en los datos (ej: infraestructura vacía en datos MITRE).

**MITRE ATT&CK vs IOCs:** MITRE documenta *comportamiento* (TTPs), no *indicadores de compromiso* (IPs, hashes). Los 0 indicadores en estas fichas son esperados y correctos.

**Timestamps en OpenCTI:** Las fechas visibles en la timeline reflejan cuándo MITRE ingresó los datos en el sistema, no cuándo APT39 usó las herramientas. Para fechas reales de actividad se necesitan objetos *Sighting* de incidentes reales.

**Malware vs Tool en STIX/OpenCTI:** `Malware` = software malicioso por naturaleza. `Tool` = software legítimo usado con fines maliciosos (NBTscan, PsExec, etc.). La distinción importa para políticas de bloqueo: bloquear NBTscan rompe operaciones de IT legítimas.

**Pivotar entre entidades:** OpenCTI permite navegar el grafo de relaciones en cualquier dirección: Malware → Actor, Actor → Arsenal, Arsenal → TTPs, TTPs → otros actores que usan la misma técnica.

---

*Documento generado el 30 de junio de 2026 | Plataforma TIM v1.1*
