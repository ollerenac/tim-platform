# Reporte Ejecutivo de Amenazas — 72 horas
**Período:** 16–19 de agosto de 2026 | **Generado:** 19 ago 2026 04:15 UTC
## 1. Resumen ejecutivo
Durante la ventana de 72 horas, la plataforma registró **187 IOCs tocados sin incorporación de nuevos indicadores**. La actividad se concentra en tres vectores de amenaza primarios: robo de credenciales (dominios de phishing y stealers), infraestructura botnet blockchain, y herramientas de acceso remoto comprometidas. Los IOCs de mayor puntuación corresponden a dominios de suplantación (phishing LastPass, DNS providers falsificados) y URLs maliciosas vinculadas a stealers de criptomonedas. No se registran nuevas variantes de malware en la ventana, pero la vigilancia activa incluye 10 familias de malware y 10 campañas de amenazas conocidas.
## 2. Cifras clave
| IOCs tocados (ventana 72h) | 187 |
| IOCs nuevos (ventana 72h) | 0 |
| IOC de máxima puntuación | 50 (pozeny.shop) |
## 3. IOCs prioritarios
| **pozeny.shop** | Domain-Name | **50** | 08 ago 2026 | credential theft, heptax, keylogger, larva-24009 |
| http://agenticsora.com/curl/ | Url | 20 | 08 ago 2026 | amos, atomic stealer, credential theft, cryptocurrency targeting |
| 78.153.155.152 | IPv4-Addr | 20 | 08 ago 2026 | blockchain c2, botnet, cve-2013-3307, cve-2016-20016 |
| lastpass-login-help.com | Domain-Name | 20 | 08 ago 2026 | container worm, docker compromise, kubernetes exploitation, pcpjack |
| dns-providersa2.com | Domain-Name | 20 | 08 ago 2026 | arrowrat, browser credential theft, lumma, nuget |
| https://aone-cli.oss-cn-beijing.aliyuncs.com/app/release/aone-cli-deps.tar.gz | Url | 20 | 08 ago 2026 | alibaba, aone-cli, china, cross-platform |
| 217.60.195.160 | IPv4-Addr | 20 | 08 ago 2026 | blockchain c2, botnet, cve-2013-3307, cve-2016-20016 |
| lenwillfilenetwork.com | Domain-Name | 20 | 08 ago 2026 | rmm abuse, splashtop, tiflux, ultravnc |
## 4. Panorama vigilado
Sable Squirrel, Darkhotel, REF7707, Cl0p, APT29, Head Mare, DeadLock, Nomadic Octopus, APT19, PittyTiger
Remcos RAT, Evooo1Bot, HiddenTear, NanoCore - S0336, DCRat, SuperShell, HackBrowserData, GateSentinel, HACKERAI C2 Agent, SHEETCORD
Quad7 Activity, CostaRicto, FLORAHOX Activity, C0027, C0026, C0017, Leviathan Australian Intrusions, C0011, Operation Wocao, Versa Director Zero Day Exploitation
T1682 T1021.002 T1025 T1497.003 T1018 T1666 T1218.002 T1589.001 T1036.010 T1418
## 5. Recomendaciones
1. Elevar prioridad de bloqueo de **pozeny.shop** (score 50, asociado a keylogger larva-24009 y actor heptax).
2. Investigar URLs en **aone-kit.oss-cn-beijing.aliyuncs.com** (4 URLs maliciosas etiquetadas como aone-cli).
3. Priorizar detección de **http://agenticsora.com/** (3 URLs distintas con patrones de C2 para cryptocurrency targeting vía Atomic Stealer y AMOS). Correlacionar con **dns-providersa2.com** y **lastpass-login-help.com**.
4. Bloquear en FW/DNS las 3 IPs de C2 blockchain (78.153.155.152, 217.60.195.160, 144.31.38.215) identificadas con CVE-2013-3307 y CVE-2016-20016.
5. Investigar **lenwillfilenetwork.com** (labels: splashtop, tiflux, ultravnc compromise). Auditar accesos administrativos remoto en período 08–19 ago.
6. La ausencia de indicadores nuevos en 72h contrasta con volumen tocado (187).
7. Cruzar etiquetas de malware/actores (PittyTiger, APT19, Darkhotel, APT29) con telemetría interna.
