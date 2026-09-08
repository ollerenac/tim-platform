# Guía simple de anotación

Una **lista cerrada** es una lista que no permite agregar ni cambiar valores.
Esta guía usa una lista cerrada: solo se permiten los tipos escritos aquí. Una
**entidad** es una cosa concreta nombrada en el texto. Un **indicador de compromiso**
es un valor técnico que puede ayudar a reconocer actividad, como una dirección
IP o un dominio. Una **relación explícita** es un vínculo que la misma frase
declara entre dos entidades. Una **frase de respaldo** es la oración completa
copiada del documento que prueba la fila. **No inferir** significa no usar
conocimiento externo, contexto implícito ni una suposición. `DUDAS` es la hoja
donde se registra una pregunta sin inventar una respuesta. Un **identificador
local** (`entity_id`) es un código corto que distingue una entidad dentro de un
documento. Una **mención exacta** es el texto copiado sin cambiar palabras.

## Orden para cada pasaje

1. Decida si hay una entidad concreta. Si no la hay, no cree fila.
2. Elija su tipo cerrado.
3. Copie la mención exacta tal como aparece.
4. **Normalizar** significa escribir una forma consistente del mismo valor;
   escriba ese valor normalizado.
5. Copie la frase de respaldo completa y la página o líneas.
6. Solo entonces busque una relación explícita entre entidades ya creadas.
7. Si falta claridad, escriba la pregunta en `DUDAS`. No adivine.

Una mención repetida reutiliza un único `entity_id` dentro de su documento. Un
**alias** es otro nombre de la misma entidad; cuenta como el mismo valor solo
cuando el texto dice la equivalencia. **Coocurrencia** significa que dos cosas
aparecen cerca; no es una relación.

## Tipos de entidad cerrados

Cada ejemplo positivo tiene una frase que sí permite una fila. Cada ejemplo
negativo muestra algo que no debe convertirse en esa fila.

| Tipo cerrado | Definición | Ejemplo positivo | Ejemplo negativo |
| --- | --- | --- | --- |
| `indicator` | Un valor técnico observable. | `192.0.2.7` aparece en una lista de actividad maliciosa. | `IP` escrito como palabra sin valor concreto. |
| `threat-actor` | Persona, grupo o actor que realiza actividad. | “LAUNDRY BEAR uses Ulej.” | “Los atacantes” sin nombre concreto. |
| `malware` | Programa malicioso nombrado. | “El malware ExampleLoader…” | “software malicioso” sin nombre. |
| `vulnerability` | Fallo técnico identificado. | “CVE-2025-66376 fue explotada.” | “una vulnerabilidad” sin identificador ni nombre. |
| `attack-pattern` | Método de ataque nombrado. | “password spraying” aparece como técnica usada. | “ataque sofisticado” como descripción vaga. |
| `campaign` | Operación o campaña nombrada. | “la campaña Flowerbed” aparece por nombre. | “la campaña actual” sin nombre propio. |
| `tool` | Herramienta o programa no clasificado como malware. | “Evilginx intercepted credentials.” | “una herramienta” sin nombre. |
| `sector` | Área de actividad o industria. | “telecommunications” es un sector objetivo. | “organizaciones grandes” no es un sector cerrado. |
| `country` | País nombrado. | “Ukraine” aparece como país. | “Europa” no es un país. |
| `technology` | Producto, servicio o tecnología nombrada. | “Zimbra Collaboration Suite” es una tecnología. | “servidor de correo” sin producto concreto. |
| `organization` | Institución, empresa u organismo nombrado. | “CISA published the advisory.” | “la agencia” sin nombre. |

## Subtipos de indicador cerrados

Un subtipo solo se llena cuando el tipo es `indicator`.

| Subtipo | Definición | Ejemplo positivo | Ejemplo negativo |
| --- | --- | --- | --- |
| `ip` | Dirección numérica de red. | `185.86.79.95` normaliza una IP desactivada. | `mail.example` no es IP. |
| `domain` | Nombre de dominio. | `emailanalytics.com.ua` normaliza `emailanalytics.com[.]ua`. | `https://emailanalytics.com.ua/a` es una URL. |
| `url` | Dirección web completa. | `https://example.test/login` es URL. | `example.test` sin ruta ni protocolo es dominio. |
| `hash_md5` | Huella MD5 de 32 caracteres hexadecimales. | `d41d8cd98f00b204e9800998ecf8427e` es MD5. | Un hash de 40 caracteres no es MD5. |
| `hash_sha1` | Huella SHA-1 de 40 caracteres hexadecimales. | `2e4f314bc9943cab5005d6fde0b271c74d47bc9d` es SHA-1. | Una cadena de 64 caracteres no es SHA-1. |
| `hash_sha256` | Huella SHA-256 de 64 caracteres hexadecimales. | `98df604ecc57f884a2e6ce3266a0013ad64455cac48442c2312cfa4765007aaf` es SHA-256. | Una cadena de 32 caracteres no es SHA-256. |
| `email` | Dirección de correo completa. | `name@example.test` es correo. | `@example.test` sin parte local no es correo. |

## Relaciones cerradas

La flecha va de origen a destino. Copie la oración que expresa esa flecha.

| Tipo | Definición | Ejemplo positivo | Ejemplo negativo |
| --- | --- | --- | --- |
| `uses` | El origen emplea el destino. | “LAUNDRY BEAR uses Ulej.” crea actor `uses` herramienta. | Actor y herramienta en párrafos distintos sin verbo de uso. |
| `targets` | El origen dirige su actividad al destino. | “Los actores target telecommunications.” crea actor `targets` sector. | Nombrar actor y sector en una tabla sin afirmar objetivo. |
| `exploits` | El origen aprovecha una vulnerabilidad. | “LAUNDRY BEAR exploits CVE-2025-66376.” crea actor `exploits` vulnerabilidad. | La vulnerabilidad se enumera sin decir quién la aprovecha. |
| `indicates` | El indicador respalda identificar al destino. | “Estos indicadores se atribuyen a LAUNDRY BEAR.” crea indicador `indicates` actor. | Una IP y un actor cercanos sin frase de atribución. |
| `attributed-to` | El origen se atribuye al destino. | “La campaña Flowerbed is attributed to LAUNDRY BEAR.” crea campaña `attributed-to` actor. | El informe menciona campaña y actor por separado. |

## Antes de entregar

Revise que toda fila tenga documento, identificador local, tipo cerrado, mención,
valor normalizado, frase de respaldo y página o líneas. Revise que cada relación
apunte a dos `entity_id` del mismo documento. Registre minutos activos una vez
en `DOCUMENTOS`; no existe un campo de minutos en `ENTIDADES`. Si una decisión
sigue incierta, deje una pregunta concreta en
`DUDAS`; no complete una relación solo para llenar la hoja.
