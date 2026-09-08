# Corpus documental — advisories de CISA con referencia oficial parcial

Cuatro Cybersecurity Advisories (TLP:CLEAR) que publican el mismo contenido dos
veces: prosa para humanos (PDF) y STIX 2.1 oficial para máquinas (.stix_.json).
El par permite **medir la concordancia** de la extracción con la representación
STIX que publicó el propio emisor. No convierte el anexo en una transcripción
exhaustiva de la prosa ni en verdad factual completa.

Recolección: manual vía navegador (2026-08-08/09). Los PDF y sus transcripciones
completas no se redistribuyen en esta exportación; sus URL y hashes se conservan
en [`SOURCES.md`](SOURCES.md). Los anexos STIX oficiales sí permanecen para la
evaluación estructurada.

## Reparto experimental — NO mover piezas entre conjuntos

| Advisory | Tema | Rol |
|---|---|---|
| AA26-204A | LAUNDRY BEAR / phishing Zimbra (ruso) | **DESARROLLO** — afinar el prompt |
| AA26-097A | PLCs / infraestructura crítica (iraní) | **TEST** — no tocar hasta evaluar |
| AA25-239A | Red de espionaje global (chino) | **TEST** — no tocar hasta evaluar |
| AA25-203A | #StopRansomware: Interlock | **TEST** — no tocar hasta evaluar |

Regla: el prompt se itera SOLO contra AA26-204A. Los tres de test se evalúan
una vez, al final, con el prompt congelado. Ajustar el prompt tras mirar un
resultado de test invalida la evaluación (fuga desarrollo→test).

## Notas de la referencia

- El STIX oficial cubre el NÚCLEO (IOCs, técnicas, actores), no todo el PDF:
  AA26-204A tiene 113 objetos frente a 31 páginas de prosa. Se usa como conjunto
  oficial de referencia parcial: lo que CISA listó debe encontrarse y cada
  objeto extra se adjudica aparte contra la prosa. La ausencia en STIX no basta
  para declarar que el objeto sea falso.
- AA26-097A lista como "malware" herramientas legítimas (SSH, Dropbear) y
  declara 6 threat-actors de granularidad dispar (IRGC → "Iranian-affiliated
  APT"). La referencia también contiene decisiones de modelado discutibles.
- Los `.stix_.xml` (STIX 1.x legado) se archivan por completitud; se trabaja
  con los `.json` (STIX 2.1).
- Estos ficheros NO se importan a OpenCTI antes de la evaluación: si la
  referencia ya está en el grafo, la salida del extractor se fusionaría con
  ella y la comparación se vuelve indistinguible. Evaluación offline, fichero
  contra fichero.

Los tests que comparan citas contra el texto completo requieren recuperar el
documento correspondiente y verificar su hash según `SOURCES.md`. Las pruebas
unitarias que construyen sus propios fixtures no requieren esos documentos.

## Integridad (sha256)

```
97805a057e1217acdf8a1c21f3852994c550b2b9fe094af270bd1bb6e24e8c76  aa26-204a/CSA_RUSSIA_PHISHING_TARGET_ZIMBRA.pdf
91f8f7e243fd82f0ac6868bd850652435bf15865eb89a27029afe305858f47ca  aa26-204a/AA26-204A.stix_.json
e0e9c7e2e2168c412c4bcc377e0964062212883d79da0f69146080ab3e355ea3  aa26-204a/AA26-204A.stix_.xml
edffdfc352331c3b793b0815108982b7da89f1bceccab694341e14c7afc8636f  aa26-097a/aa26-097a-iranian-plc_508c.pdf
079eb0f5eaeb15988f3bedf4c7f57b5f8bacfcef046cd9756b4df13ad3fc7c7b  aa26-097a/AA26-097A.stix_.json
1d0619d9908ee7b0a4dcf13ff24762643d4ab2844559fbd2eb562c03435f5e40  aa25-239a/CSA_COUNTERING_CHINA_STATE_ACTORS_COMPROMISE_OF_NETWORKS.pdf
c391051766cd76666740408682f5fa5d9fa25ed552d853543e6a82ac1fe4058a  aa25-239a/AA25-239A.stix_.json
23a7f30ae72261ce9e6e18062bd48077143a9a5e1045bf905029cbeacfadafa2  aa25-203a/aa25-203a-stopransomware-interlock-072225.pdf
c084b40e67e96e116478c79355a665c5cc89e414d1df66162845c7d64aae10cf  aa25-203a/AA25-203A-interlock-stix.json
```

Fuente: https://www.cisa.gov/news-events/cybersecurity-advisories (tipo
Cybersecurity Advisory). Esta exportación referencia los documentos completos
por URL y hash en lugar de republicarlos.
