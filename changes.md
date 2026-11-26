# Veredicto

**r2morph está en una *alpha avanzada* como framework general y en una *beta controlada/de laboratorio* para su ruta más madura: virtualización de código en ELF x86-64.**

Mi valoración global actual es de **5/10 de madurez**:

| Área                         |    Madurez | Valoración                                                         |
| ---------------------------- | ---------: | ------------------------------------------------------------------ |
| Arquitectura interna         | **7,5/10** | Bien separada, extensible y con controles de seguridad             |
| Virtualización ELF x86-64    |   **6/10** | Funciona en escenarios controlados y tiene pruebas nativas         |
| Transformaciones generales   |   **5/10** | Bastante superficie implementada, evidencia desigual               |
| PE, Mach-O, ARM y AArch64    | **3–4/10** | Soporte todavía experimental o parcial                             |
| Calidad y pruebas            |   **5/10** | Mucha inversión en testing, pero reproducibilidad inconsistente    |
| Seguridad frente a analistas |   **4/10** | Resultados prometedores, aún sin validación adversarial suficiente |
| Preparación para release     |   **3/10** | El `main` actual no está verde en CI                               |
| Preparación para producción  |   **3/10** | Aún no ofrece un contrato de soporte suficientemente cerrado       |

No lo considero un simple prototipo. Hay una base de ingeniería seria. Pero tampoco lo presentaría todavía como un protector multiplataforma listo para proteger software real frente a ingeniería inversa profesional.

La mejor definición comercial/técnica hoy sería:

> **Framework experimental de transformación y virtualización de binarios, con soporte avanzado y controlado para ELF x86-64.**

No todavía:

> “Protector universal de ELF, PE y Mach-O para cuatro arquitecturas.”

---

# Lo mejor del proyecto

## 1. La arquitectura está bien planteada

El flujo interno está separado en parsing, validación, planificación de pases, transformación, reensamblado y verificación. También hay dependencias y conflictos entre pases, orden determinista, políticas de seguridad, modos operativos y comprobaciones que intentan fallar de forma cerrada antes de producir un binario incorrecto. Eso es mucho más maduro que acumular mutaciones directamente sobre bytes.

La separación entre:

* núcleo,
* API,
* CLI,
* pipeline,
* pases,
* análisis,
* patrones,
* seguridad,
* transparencia y auditoría,

te deja una base adecuada para evolucionar hacia un producto serio.

## 2. Hay una inversión real en ingeniería de calidad

El proyecto incluye Ruff, mypy, Semgrep, `pip-audit`, OSV, generación de SBOM, Hypothesis, cobertura, pruebas en distintos sistemas y versiones de Python, pruebas de paquetes y validaciones de seguridad operacional. No es el típico proyecto de investigación que solo funciona desde el entorno del autor.

El informe automático incluido en el repositorio afirma, para su entorno de auditoría, **4.868 tests superados, 21 omitidos, 11 módulos de transformaciones y entre 25 y 30 pases según el contador utilizado**. Es una cifra notable, aunque debe interpretarse como evidencia generada por el propio repositorio, no como una certificación independiente.

## 3. El virtualizador ELF x86-64 ya tiene sustancia

La documentación de madurez del virtualizador presenta pruebas de:

* bloques aritméticos;
* múltiples bloques básicos;
* dependencias entre registros;
* uso de stack;
* bifurcaciones y bucles;
* compilación, virtualización y ejecución real de ELF.

El informe contabiliza 154 pruebas específicas, entre ellas 17 casos nativos de compilación → transformación → ejecución, y lo clasifica como apto para “uso controlado”. También obtiene una valoración interna de análisis dinámico de 84/100.

Eso significa que **sí existe un núcleo técnico demostrable**. No es solo una colección de clases, interfaces y pases ficticios.

## 4. La documentación reconoce limitaciones

El README no oculta que:

* ELF x86-64 es el objetivo más maduro;
* la virtualización completa se concentra en ELF x86-64;
* requiere análisis adicional mediante angr;
* la cobertura de instrucciones es limitada;
* puede aumentar considerablemente el tamaño;
* algunos pases basados en patrones pueden producir falsos positivos o negativos;
* AArch64 y otros objetivos funcionan en modalidad de mejor esfuerzo;
* el resultado debe validarse antes de usarse en producción.

Esa honestidad técnica es positiva. El problema no está tanto en las advertencias, sino en que la portada general puede transmitir más homogeneidad de soporte de la que realmente existe.

---

# El principal problema actual: `main` está rojo

A fecha de **25 de agosto de 2026**, el último workflow publicado para el `HEAD` actual, ejecutado el 21 de agosto, terminó en fallo.

El job de pruebas unitarias ni siquiera llegó a ejecutar la suite:

* el control de inventario localizó 3.832 tests;
* durante la recogida aparecieron errores `ModuleNotFoundError: No module named 'r2morph'`;
* se ejecutaron cero tests;
* no se generó `coverage.xml`.

Esto parece, en ese job concreto, un problema de instalación o importación del paquete, no necesariamente una regresión del motor. Sin embargo, también aparecen fallos independientes en:

* pruebas de integración;
* fixtures entre versiones de Python;
* fixtures multiplataforma;
* Windows;
* macOS con Python 3.13.

Mientras esos jobs no estén investigados, no puede asumirse que todo el problema sea únicamente un `pip install -e .` ausente.

Por tanto:

**No haría ahora mismo una release estable ni una beta pública promovida como confiable.**

Sí podrías publicar una **`0.4.0-alpha.1`**, pero únicamente después de restaurar el CI y delimitar claramente el soporte.

---

# La mayor asimetría de madurez

r2morph tiene dos niveles distintos que ahora aparecen demasiado mezclados.

## Nivel A: lo realmente demostrado

* Linux.
* ELF.
* x86-64.
* Un subconjunto definido de transformaciones.
* Virtualización de funciones relativamente contenidas.
* Pruebas nativas end-to-end.
* Uso de laboratorio, investigación y evaluación controlada.

Esto está alrededor de **6/10**.

## Nivel B: la visión global del producto

* ELF, PE y Mach-O.
* x86, x86-64, ARM y AArch64.
* Numerosos pases combinables.
* Virtualización y protecciones contra análisis.
* Experiencia homogénea en varios sistemas.
* Uso en binarios reales y complejos.

Esto está alrededor de **3–4/10**, porque la cobertura funcional y la evidencia no son equivalentes en todos los objetivos. El propio README describe ELF como estable, PE como alpha y Mach-O como experimental, mientras que la integración más madura sigue siendo ELF x86-64.

La solución no es retirar características, sino **hacer explícita una matriz de soporte por capacidad**.

---

# Qué falta técnicamente

## 1. Reproducibilidad real

Tienes una auditoría que afirma 4.868 pruebas superadas, mientras el workflow actual inventaría 3.832 tests y después falla antes de ejecutarlos. No significa necesariamente que una cifra sea falsa: pueden estar contabilizando casos distintos, dependencias opcionales o entornos diferentes. Pero sí demuestra que actualmente no existe una única fuente reproducible de verdad.

Hay que garantizar que:

1. un desarrollador clona el repositorio;
2. instala mediante un comando documentado;
3. ejecuta exactamente la misma suite que CI;
4. obtiene el mismo inventario;
5. produce el mismo paquete;
6. ejecuta las pruebas sobre el paquete instalado, no solo sobre el árbol fuente.

## 2. Contrato preciso de compatibilidad

“Implementado” no debería equivaler a “soportado”.

Cada combinación debería tener estados separados:

* código presente;
* unidad probada;
* fixture probado;
* ejecutado de forma nativa;
* probado sobre corpus real;
* sometido a fuzzing;
* oficialmente soportado.

Por ejemplo:

| Pase                     | ELF x86-64         | ELF AArch64  | PE x86-64    | Mach-O ARM64 |
| ------------------------ | ------------------ | ------------ | ------------ | ------------ |
| Instruction substitution | Soportado          | Experimental | Alpha        | Experimental |
| Control-flow flattening  | Soportado limitado | Experimental | Experimental | No soportado |
| Code virtualization      | Beta controlada    | No soportado | No soportado | No soportado |

Esto evitará que el usuario confunda la existencia de un backend con una garantía funcional.

## 3. Semántica incompleta del virtualizador

La propia evaluación de madurez identifica carencias importantes:

* acceso de memoria con determinadas semánticas de dirección;
* llamadas a funciones;
* llamadas indirectas;
* punto flotante y SIMD;
* varargs;
* excepciones y unwinding;
* threads;
* señales;
* análisis estático de liveness/SSA.

El diseño actual depende en parte de ejecución simbólica dinámica, lo que limita la cobertura de caminos y puede hacer que un comportamiento no observado durante el levantamiento quede fuera de la traducción.

Para un virtualizador comercial, las llamadas, memoria y cobertura de instrucciones no son mejoras secundarias: son bloqueantes para proteger funciones reales.

## 4. Validación adversarial

La evaluación reconoce que no se ha hecho todavía fuzzing ni pentesting específico del protector. También hay un benchmark estático prometedor —reducción de ensamblado y complejidad visible en una función pequeña—, pero una única función diminuta no demuestra resistencia general contra IDA, Ghidra, angr, Triton o ataques personalizados. Binary Ninja queda como herramienta opcional si ya está disponible; no se necesita ni se solicitará una licencia.

Necesitas medir por separado:

* corrección semántica;
* resistencia estática;
* resistencia dinámica;
* coste de ejecución;
* crecimiento del binario;
* automatización de la desvirtualización.

## 5. Deriva entre versión, documentación y realidad

El paquete continúa identificado como **0.3.0**, mientras el repositorio ha crecido mucho desde esa release.

Además, aparecen diferentes cifras:

* 18 pases anunciados en el README;
* 25 pases en el registro;
* 30 pases activos según el audit;
* 4.868 tests en el audit actual;
* 212 tests mencionados en la release 0.3.0 de marzo de 2026.

Esto no es un defecto del motor, pero sí de madurez de producto. Los contadores deberían generarse automáticamente desde el código y la suite.

---

# Roadmap recomendado

## P0 — Dejar el proyecto en estado publicable

### 1. Poner `main` completamente verde

No aceptaría como suficiente arreglar solo el import.

El objetivo debería ser:

* instalar primero el wheel construido;
* verificar `import r2morph`;
* ejecutar tests contra el wheel;
* ejecutar una segunda suite sobre el checkout si es necesario;
* solucionar todos los fallos de Windows y macOS;
* hacer obligatorios los jobs de la plataforma oficialmente soportada;
* evitar que jobs críticos queden omitidos por dependencias fallidas.

Añadiría explícitamente:

```bash
python -m build
python -m pip install --force-reinstall dist/*.whl
python -c "import r2morph; print(r2morph.__version__)"
python -m pytest
r2morph --version
```

### 2. Declarar un objetivo oficialmente soportado

Para la próxima release:

> **Soporte oficial inicial: Linux ELF x86-64.**

Y clasificaría el resto como:

* PE x86-64: preview/alpha;
* Mach-O: experimental;
* x86: experimental;
* AArch64/ARM: experimental;
* virtualización: solo ELF x86-64 y funciones compatibles.

Eso no empequeñece el proyecto. Al contrario: convierte una promesa difusa en un producto verificable.

### 3. Publicar `0.4.0-alpha.1`

No mantendría el identificador 0.3.0 para el estado actual.

La `0.4.0-alpha.1` debería incluir:

* matriz de soporte;
* inventario generado automáticamente;
* changelog;
* lista de limitaciones por pase;
* estado del CI;
* corpus exacto utilizado;
* commit asociado a cada informe de madurez.

### 4. Añadir gates de release

Como mínimo:

* 100 % de jobs obligatorios verdes;
* instalación y prueba del wheel;
* smoke test del CLI y API;
* mínimo inicial de cobertura, por ejemplo 75–80 %;
* cero fallos en corpus soportado;
* cero skips de pruebas críticas;
* generación de SBOM y provenance;
* comprobación automática de enlaces y contadores de documentación.

---

## P1 — Demostrar corrección sobre binarios reales

### 5. Crear un corpus de compatibilidad

Construiría un corpus público o reproducible con:

* GCC y Clang;
* `-O0`, `-O1`, `-O2`, `-O3`, `-Os`;
* PIE y no PIE;
* símbolos y stripped;
* linking dinámico y, cuando sea viable, estático;
* C y C++;
* funciones con switch, bucles, recursión y punteros;
* TLS;
* excepciones C++;
* binarios reales pequeños y medianos.

Cada muestra debe registrar:

* transformación aplicada;
* si fue omitida y por qué;
* resultado de ejecución;
* diferencia de rendimiento;
* diferencia de tamaño;
* resultado en IDA y Ghidra; Binary Ninja es opcional cuando esté disponible y
  su ausencia no bloquea la evaluación ni una release.

### 6. Hacer pruebas diferenciales

Para cada transformación:

1. ejecutar original;
2. ejecutar transformado;
3. comparar código de salida;
4. comparar stdout y stderr;
5. comparar archivos creados;
6. comparar efectos observables;
7. repetir con entradas generadas por propiedades y fuzzing.

No basta con comprobar que el binario transformado no se cae. Debe comportarse igual.

### 7. Asignar madurez individual a cada pase

Cada pase debería tener su propio informe:

* formatos soportados;
* arquitecturas;
* precondiciones;
* invariantes;
* instrucciones afectadas;
* riesgo de falso positivo;
* pruebas unitarias;
* pruebas end-to-end;
* impacto en rendimiento;
* eficacia frente a decompiladores;
* compatibilidad con otros pases.

Así podrás seleccionar un pequeño conjunto de pases “Tier 1” y dejar el resto como experimental.

---

## P2 — Completar el virtualizador

El orden que recomiendo es:

1. **loads y stores de memoria completos**;
2. **calls y returns directos**;
3. **llamadas indirectas**;
4. **cobertura amplia de flags e instrucciones**;
5. **punto flotante y SIMD**;
6. **varargs y ABI complejas**;
7. **excepciones y unwinding**;
8. **threads, TLS y señales**.

Mientras una función utilice una construcción no soportada, el motor debería:

* detectarla antes de transformar;
* rechazarla de forma cerrada;
* indicar la instrucción y dirección responsable;
* explicar qué capacidad falta;
* no producir un binario parcialmente virtualizado sin advertencia.

Después incorporaría un análisis estático de SSA/liveness o un modelo híbrido estático-simbólico. La ejecución simbólica es útil, pero no debería ser la única fuente de verdad sobre la semántica de una función.

---

## P3 — Resistencia real frente a ingeniería inversa

Una vez consolidada la corrección:

### 8. Benchmark de herramientas

Automatizaría evaluaciones contra:

* IDA Pro;
* Ghidra;
* Binary Ninja, opcional e informativo; no requiere licencia para este proyecto
  y su indisponibilidad no bloquea el benchmark ni la release;
* radare2;
* angr;
* Triton;
* emulación Unicorn;
* scripts propios de recuperación de CFG;
* identificación de handlers de VM;
* ataques de simplificación simbólica.

Mediría:

* funciones correctamente detectadas;
* CFG recuperado;
* pseudocódigo producido;
* similitud respecto al original;
* tiempo de análisis;
* posibilidad de identificar y extraer handlers;
* porcentaje de instrucciones virtuales simplificables.

### 9. Diversificación de la VM

Ahora mismo una VM funcional no implica una VM resistente.

Las siguientes capacidades serían:

* ISA virtual distinta por build o función;
* permutación de opcodes;
* handlers diversificados;
* dispatchers alternativos;
* superinstructions;
* codificación contextual;
* separación y fragmentación de handlers;
* integridad y anti-tamper;
* cifrado progresivo del bytecode;
* constantes protegidas;
* transformación dependiente de claves de build.

La prioridad debe ser evitar que desarrollar un desvirtualizador para una muestra permita resolver automáticamente todas las demás.

### 10. Fuzzing y revisión independiente

Como mínimo:

* fuzzing de parsers;
* fuzzing del decodificador y dispatcher de VM;
* fuzzing de relocations;
* fuzzing del ensamblado y reescritura;
* propiedades “original == transformado”;
* corpus de binarios malformados;
* revisión externa por alguien especializado en binary rewriting y virtualización.

---

# Cuándo consideraría que está en beta

Marcaría una beta cuando se cumplan simultáneamente estas condiciones:

* `main` verde de forma continuada;
* wheel instalado y probado en CI;
* soporte oficial restringido y documentado;
* todos los pases soportados con pruebas nativas;
* corpus real reproducible;
* pruebas diferenciales;
* primera campaña de fuzzing;
* métricas de rendimiento y crecimiento;
* cero defectos críticos conocidos en el objetivo soportado;
* workflow de release ejecutado de principio a fin.

# Cuándo consideraría que está en 1.0

Para una 1.0 exigiría:

* API y CLI estables;
* política de compatibilidad y deprecación;
* matriz de soporte contractual;
* cobertura amplia de funciones reales;
* corpus público o reproducible;
* fuzzing continuo;
* revisión independiente;
* artefactos firmados;
* SBOM y provenance;
* resultados publicados de corrección, coste y resistencia;
* al menos un formato y una arquitectura con soporte verdaderamente completo.

---

# Mi prioridad exacta para las próximas semanas

El orden óptimo sería:

1. **Arreglar todo el CI, no solo el `ModuleNotFoundError`.**
2. **Congelar el soporte oficial en ELF x86-64.**
3. **Crear la matriz pase × formato × arquitectura × evidencia.**
4. **Publicar `0.4.0-alpha.1`.**
5. **Introducir pruebas del wheel instalado.**
6. **Crear corpus diferencial GCC/Clang.**
7. **Seleccionar entre cinco y ocho pases Tier 1.**
8. **Añadir fuzzing de parsers y equivalencia semántica.**
9. **Completar memoria y llamadas en el virtualizador.**
10. **Montar el benchmark automatizado contra decompiladores.**

La conclusión importante es que **no necesitas añadir veinte protecciones nuevas ahora**. El mayor salto de madurez vendrá de demostrar de forma reproducible que un subconjunto más pequeño funciona correctamente, en binarios reales y frente a herramientas reales. Después podrás ampliar formatos y arquitecturas sin que la superficie experimental crezca más rápido que la evidencia.

No pude ejecutar personalmente toda la suite en un clon local debido a las restricciones de red del entorno; por eso trato las 4.868 pruebas del informe interno como una cifra declarada por el repositorio. La situación del workflow público y sus errores sí corresponde al `HEAD` inspeccionado.
