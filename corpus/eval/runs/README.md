# Artefactos del caso AA26-204A

Este directorio conserva los artefactos del documento usado para desarrollar el
prompt de extraccion. No constituyen una ejecucion de extremo a extremo del
extractor desplegado ni forman parte del conjunto final de prueba.

## Versiones

- `aa26-204a.v2.1.json` es el artefacto vigente. Fue ensamblado a partir de una
  sesion de desarrollo del prompt; el script `../build_run_v21.py` genera las
  tablas repetitivas para evitar errores de transcripcion.
- `aa26-204a.v2.0.json` es la copia historica restaurada desde el commit
  `74da56d`; `../build_run_v20.py` permite reconstruirla.

La version v2.0 contenia 97 entidades y 58 relaciones (155 objetos); v2.1
contiene 106 entidades y 67 relaciones (173 objetos). Estos conteos describen
artefactos de desarrollo, no rendimiento general del sistema.

Los dos constructores repiten deliberadamente parte del ensamblaje para
conservar cada version congelada. Cualquier refactor futuro debe mantener la
prueba que exige reproduccion byte por byte de ambos JSON.

## Interpretacion de `score.py`

El corrector compara el JSON intermedio con el anexo STIX oficial de CISA. Ese
anexo es una referencia oficial pero parcial: no agota los objetos sustentados
por la prosa del advisory. Por ello, precision, exhaustividad y F1 deben
rotularse como concordancia con STIX (`P_STIX`, `R_STIX`, `F1_STIX`). Un objeto
extra que no figure en STIX requiere adjudicacion manual contra la prosa antes
de considerarse falso positivo factual.

La medicion final debe ejecutarse sobre documentos reservados que no hayan sido
usados para modificar el prompt. Mientras esa prueba no se complete, los
resultados de AA26-204A solo sustentan observaciones del caso de desarrollo.
