# Clave de respuestas de práctica

Esta clave se entrega separada de `practice.xlsx`. El libro de práctica debe
seguir vacío en `ENTIDADES` y `RELACIONES`; las filas de abajo son para revisar
después de intentar los dos documentos.

## Entidades

| document_id | entity_id | entity_type | indicator_subtype | normalized_value | mention_as_written | supporting_quote | page_or_lines | certainty | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| practice-aa25-239a-narrative | e1 | threat-actor | - | PRC state-sponsored cyber threat actors | People’s Republic of China (PRC) state-sponsored cyber threat actors | People’s Republic of China (PRC) state-sponsored cyber threat actors are targeting networks globally, including, but not limited to, telecommunications, government, transportation, lodging, and military infrastructure networks. | page 1 | clear | Actor nombrado en la oración. |
| practice-aa25-239a-narrative | e2 | sector | - | telecommunications | telecommunications | People’s Republic of China (PRC) state-sponsored cyber threat actors are targeting networks globally, including, but not limited to, telecommunications, government, transportation, lodging, and military infrastructure networks. | page 1 | clear | Sector incluido explícitamente. |
| practice-aa26-204a-indicators | e1 | threat-actor | - | LAUNDRY BEAR | LAUNDRY BEAR | The following indicators have been attributed to use by LAUNDRY BEAR for their campaign targeting ZCS’s webmail service as of the publication of this advisory. | page 20 | clear | Actor nombrado en la frase de atribución. |
| practice-aa26-204a-indicators | e2 | indicator | domain | emailanalytics.com.ua | emailanalytics.com[.]ua | emailanalytics.com[.]ua 185.86.79[.]95 24 September 2025 18 March 2026 | page 21 | clear | El dominio se normaliza al quitar `[.]`. |
| practice-aa26-204a-indicators | e3 | indicator | ip | 185.86.79.95 | 185.86.79[.]95 | emailanalytics.com[.]ua 185.86.79[.]95 24 September 2025 18 March 2026 | page 21 | clear | La IP se normaliza al quitar `[.]`. |

## Relaciones

| document_id | relationship_id | source_entity_id | relationship_type | target_entity_id | supporting_quote | page_or_lines | certainty | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| practice-aa25-239a-narrative | r1 | e1 | targets | e2 | People’s Republic of China (PRC) state-sponsored cyber threat actors are targeting networks globally, including, but not limited to, telecommunications, government, transportation, lodging, and military infrastructure networks. | page 1 | clear | La frase dice que el actor dirige actividad hacia el sector. |
| practice-aa26-204a-indicators | r1 | e2 | indicates | e1 | The following indicators have been attributed to use by LAUNDRY BEAR for their campaign targeting ZCS’s webmail service as of the publication of this advisory. <br> emailanalytics.com[.]ua 185.86.79[.]95 24 September 2025 18 March 2026 | pages 20-21 | clear | La oración atribuye la lista; la fila de Tabla 7 identifica este dominio. |
| practice-aa26-204a-indicators | r2 | e3 | indicates | e1 | The following indicators have been attributed to use by LAUNDRY BEAR for their campaign targeting ZCS’s webmail service as of the publication of this advisory. <br> emailanalytics.com[.]ua 185.86.79[.]95 24 September 2025 18 March 2026 | pages 20-21 | clear | La oración atribuye la lista; la fila de Tabla 7 identifica esta IP. |

## Explicaciones

- AA25-239A es la práctica narrativa: permite separar actor, sector y relación
  sin convertir todas las palabras técnicas en entidades.
- AA26-204A concentra indicadores en una tabla: permite practicar subtipo,
  desactivación `[.]` y respaldo de atribución.
- No se añade una relación entre dominio e IP: compartir una fila de tabla no
  expresa por sí solo uno de los cinco tipos de relación cerrados.
