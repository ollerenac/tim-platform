# Reporte Ejecutivo de Amenazas — Ventana 72h

**Período:** 2026-08-16 a 2026-08-19 | **Generado:** 2026-08-19 04:21 UTC

---

## 1. Resumen Ejecutivo

Durante la ventana de 72 horas, la plataforma monitoreó **187 IOCs tocados** sin registro de nuevas incorporaciones (0 IOCs nuevos). La actividad se concentra en infraestructura comprometida asociada a robo de credenciales, malware multiplataforma alojado en servicios Alibaba, y nodos de comando y control vinculados a botnets. El dominio **pozeny.shop** (score 50) destaca como amenaza prioritaria por múltiples vectores maliciosos. No se registra actividad adversaria atribuible a ventana actual, pero la vigilancia de plataforma identifica 10 actores y 10 familias de malware activos en el contexto operacional.

---

## 2. Cifras Clave

| Métrica | Valor |
|---------|-------|
| IOCs tocados en ventana | 187 |
| IOCs nuevos en ventana | 0 |
| Dominios en IOCs prioritarios | 4 |
| URLs en IOCs prioritarios | 6 |
| IPv4 en IOCs prioritarios | 3 |
| Score máximo detectado | 50 (pozeny.shop) |
| Fecha común de creación IOCs | 2026-08-08 |

---

## 3. IOCs Prioritarios

| Valor | Tipo | Score | Fecha Creación | Labels |
|-------|------|-------|-----------------|--------|
| pozeny.shop | Domain-Name | 50 | 2026-08-08 | credential theft, heptax, keylogger, larva-24009 |
| https://aone-ai-cli.oss-cn-beijing.aliyuncs.com/app/release/aone-cli-deps.tar.gz | Url | 20 | 2026-08-08 | alibaba, aone-cli, china, cross-platform |
| 78.153.155.152 | IPv4-Addr | 20 | 2026-08-08 | blockchain c2, botnet, cve-2013-3307, cve-2016-20016 |
| http://agenticsora.com/curl/ | Url | 20 | 2026-08-08 | amos, atomic stealer, credential theft, cryptocurrency targeting |
| 217.60.195.160 | IPv4-Addr | 20 | 2026-08-08 | blockchain c2, botnet, cve-2013-3307, cve-2016-20016 |
| lenwillfilenetwork.com | Domain-Name | 20 | 2026-08-08 | rmm abuse, splashtop, tiflux, ultravnc |
| dns-providersa2.com | Domain-Name | 20 | 2026-08-08 | arrowrat, browser credential theft, lumma, nuget |
| lastpass-login-help.com | Domain-Name | 20 | 2026-08-08 | container worm, docker compromise, kubernetes exploitation, pcpjack |
| 144.31.38.215 | IPv4-Addr | 20 | 2026-08-08 | blockchain c2, botnet, cve-2013-3307, cve-2016-20016 |

---

## 4. Panorama Vigilado

**Nota:** Los actores, malware y campañas listados representan conocimiento vigilado por la plataforma (ordenado por actividad de escritura reciente). No corresponden necesariamente a actividad detectada en la ventana actual.

### Actores Seguidos (última actividad de escritura: 2026-08-15)

| Actor | Descripción |
|-------|-------------|
| Sable Squirrel | — |
| Darkhotel | Grupo amenaza sospechosamente de origen Corea del Sur; objetivo primario Asia Oriental desde 2004+ |
| REF7707 | — |
| Cl0p | — |
| APT29 | Grupo amenaza atribuido a Servicio de Inteligencia Extranjera (SVR) ruso |
| Head Mare | — |
| DeadLock | — |
| Nomadic Octopus | Grupo de espionaje cibernético ruso-hablante; objetivo primario Asia Central (gobiernos locales, misiones diplomáticas) |
| APT19 | Grupo amenaza con base en China; objetivo múltiples industrias (defensa, finanzas, energía, farmacéutica, telecomunicaciones) |
| PittyTiger | Grupo amenaza operar desde China; uso múltiple tipos malware para C2 |

### Malware Seguido (última actividad de escritura: 2026-08-15)

- Remcos RAT
- Evooo1Bot
- HiddenTear
- NanoCore - S0336
- DCRat
- SuperShell
- HackBrowserData
- GateSentinel
- HACKERAI C2 Agent
- SHEETCORD

### Campañas Vigiladas (última actividad de escritura: 2026-08-15)

- Quad7 Activity (botnet SOHO 7777)
- CostaRicto (espionaje hacker-for-hire, objetivo financiero)
- FLORAHOX Activity (infraestructura ORB híbrida)
- C0027 (Scattered Spider, telecomunicaciones y negocios)
- C0026 (distribución selectiva KOPILUWAK/QUIETEATER, sep-2022)
- C0017 (APT41, may-2021 a feb-2022)
- Leviathan Australian Intrusions (espionaje larga duración, Australia)
- C0011 (Transparent Tribe, objetivo estudiantes universitarios)
- Operation Wocao (espionaje global multiregional)
- Versa Director Zero Day Exploitation (Volt Typhoon, jun-ago 2024)

### Técnicas ATT&CK Asociadas

- **T1682** — Query Public AI Services
- **T1021.002** — SMB/Windows Admin Shares
- **T1025** — Data from Removable Media
- **T1497.003** — Time Based Checks
- **T1018** — Remote System Discovery
- **T1666** — Modify Cloud Resource Hierarchy
- **T1218.002** — Control Panel
- **T1589.001** — Credentials
- **T1036.010** — Masquerade Account Name
- **T1418** — Software Discovery

---

## 5. Recomendaciones

1. **Bloquear pozeny.shop y asociados de inmediato.** Este dominio (score 50, creado 2026-08-08) es vector primario de robo de credenciales y keylogger; las labels incluyen larva-24009 e heptax. Escalar a equipo de defensa perimetral para blocklist DNS y proxy.

2. **Auditar descarga y ejecución desde hosts Alibaba OSS-CN-Beijing.** Tres URLs (aone-cli-deps.tar.gz, crypto.js, app.asar) con score 20 alojan malware multiplataforma etiquetado como china/cross-platform; implementar restricción de descarga desde dominios Alibaba no-sancionados.

3. **Investigar conectividad a direcciones IP de C2 blockchain.** Los tres nodos (78.153.155.152, 217.60.195.160, 144.31.38.215) comparten labels "blockchain c2, botnet" y vulnerabilidades CVE-2013-3307, CVE-2016-20016; verificar logs de firewall/proxy en últimos 10 días.

4. **Monitorear intentos de acceso a credenciales desde agenticsora.com.** Cuatro URLs (curl/, dynamic, gate/*) están marcadas credential theft y cryptocurrency targeting (amos/atomic stealer); correlacionar con eventos de robo browser y cartera criptográfica en SIEM.

5. **Validar ausencia de herramientas RMM en red corporativa.** lenwillfilenetwork.com y dns-providersa2.com indican abuso de Splashtop, UltraVNC, Arrowrat y Lumma; ejecutar scan de procesos y conexiones de red para detectar sesiones RMM anómalas.

6. **Reforzar contraseña de credenciales LastPass en organización.** El dominio lastpass-login-help.com es squatting de phishing asociado a compromiso de contenedor Docker/Kubernetes (pcpjack); instruir cambio forzado de credenciales LastPass y auditoría de logs de acceso delegado.

7. **Correlacionar ATT&CK T1589.001 (recolección de credenciales) con incidentes internos.** La técnica está presente en panorama vigilado; revisar eventos de descarga de navegador credential dumpers (HackBrowserData) en últimos 30 días y enriquecer timeline de investigación.
