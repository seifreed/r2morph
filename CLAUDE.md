# r2morph — Reglas de calidad y arquitectura

Estas reglas son **vinculantes** para cualquier cambio en este repositorio. No son recomendaciones. Toda contribución (humana o asistida por IA) debe cumplirlas antes de hacer commit.

---

## 1. Prohibido suprimir checks de forma inline

Queda **prohibido** introducir, mantener o reactivar cualquier supresión inline, comentario de bypass o exclusión local que silencie a un linter, type checker, escáner de seguridad o medidor de cobertura. Esto aplica tanto al código fuente como a los ficheros de configuración (`pyproject.toml`, `setup.cfg`, `.bandit`, `.coveragerc`, `mypy.ini`, `ruff.toml`, etc.).

Patrones prohibidos (lista no exhaustiva):

| Herramienta    | Supresión prohibida                                                                 |
|----------------|--------------------------------------------------------------------------------------|
| Bandit         | `# nosec`, `# nosec B###`, `[tool.bandit] skips = [...]`, `exclude_dirs` por conveniencia |
| Coverage.py    | `# pragma: no cover`, `exclude_lines = [...]`, `omit = [...]` para esquivar cobertura |
| mypy           | `# type: ignore`, `# type: ignore[code]`, `ignore_missing_imports = true`, `ignore_errors = true`, overrides de módulo que silencien errores |
| Ruff / flake8  | `# noqa`, `# noqa: XYZ`, `ignore = [...]` en `[tool.ruff.lint]`, `per-file-ignores`     |
| Black          | `# fmt: off`, `# fmt: skip`, `force-exclude` para esquivar formato                     |
| pip-audit      | `--ignore-vuln`, listas de CVEs ignoradas, exclusión de paquetes                       |
| pytest         | `filterwarnings = ["ignore::..."]`, `@pytest.mark.filterwarnings("ignore")`, `-W ignore` |

**Excepciones**: ninguna por defecto. Si un caso concreto **demuestra técnicamente** que no hay alternativa (p.ej., un stub de dependencia opcional ausente en plataforma X), debe:

1. Documentarse en este CLAUDE.md bajo una sección "Excepciones aprobadas" con justificación técnica, fecha, autor y commit asociado.
2. Acotarse al símbolo/línea mínima imprescindible.
3. Llevar comentario explicando **por qué** no es resoluble de otra forma.
4. Revisarse en cada release; si la causa raíz desaparece, la supresión se elimina.

No vale "es que falla en CI" ni "lo arreglo luego". Si el check falla, **se arregla el código**, no se silencia la herramienta.

---

## 2. `pyproject.toml` — completo y sin atajos

`pyproject.toml` debe contener configuración completa y estricta para **todas** las herramientas del stack:

- `[tool.black]` — sin `force-exclude` para esquivar formato; line-length consistente.
- `[tool.ruff]` / `[tool.ruff.lint]` — `select` amplio (mínimo `E`, `F`, `W`, `B`, `S`, `I`, `N`, `UP`, `SIM`, `PL`, `RUF`). `ignore = []` vacío. Sin `per-file-ignores` por conveniencia.
- `[tool.mypy]` — `strict = true` o equivalente (`disallow_untyped_defs = true`, `disallow_any_generics = true`, `warn_return_any = true`, `warn_unused_ignores = true`, `warn_redundant_casts = true`, `warn_unreachable = true`, `strict_equality = true`, `no_implicit_optional = true`). Sin `ignore_missing_imports` global.
- `[tool.bandit]` — definido explícitamente. `skips = []`. Severidad mínima `LOW`. Confianza mínima `LOW`. Sin `exclude_dirs` salvo `tests/` y artefactos de build.
- `[tool.coverage.run]` — `branch = true`. `omit = []` (o lista mínima justificada por documento adjunto). Sin omits de módulos de producción.
- `[tool.coverage.report]` — `exclude_lines = []` por defecto; `fail_under` ≥ umbral acordado del proyecto.
- `[tool.pytest.ini_options]` — `filterwarnings = ["error"]` (los warnings son errores). Sin `ignore::...`.
- `[project]` — `dependencies` y `optional-dependencies` con cotas inferiores explícitas. Sin dependencias sin pinned mínimo.

Si una sección no existe en `pyproject.toml` cuando la herramienta se usa en el proyecto, se considera **omisión** y debe añadirse antes de hacer merge.

---

## 3. Herramientas obligatorias — cero errores, cero warnings

Antes de cualquier commit, PR o release, **todas** las siguientes deben ejecutarse y pasar **sin errores ni warnings**:

```bash
black --check .
ruff check .
mypy r2morph
bandit -r r2morph -c pyproject.toml
pip-audit
pytest -W error
```

Reglas:

- **No se acepta "warning" como aceptable**. Un warning es un error sin resolver.
- **No se ejecutan en modo permisivo**: nada de `--exit-zero`, `--soft-fail`, `|| true`, ni redirección a `/dev/null`.
- **No se omiten ficheros** del scope de ejecución para "ahorrar tiempo".
- **CI debe fallar** si alguna de estas herramientas produce output distinto a "all checks passed" / equivalente limpio.
- Si una versión de la herramienta introduce un nuevo check que rompe el build, se ajusta el código; **no se downgradea la herramienta** ni se ignora el check.

Stack mínimo de versiones (cotas inferiores, no superiores):

- `black >= 23.0.0`
- `ruff >= 0.1.0` (preferir la última estable)
- `mypy >= 1.5.0`
- `bandit >= 1.7.5`
- `pip-audit >= 2.6.0`
- `pytest >= 7.4.0`

---

## 4. Tests reales — sin mocks ni monkeypatch

Los tests verifican comportamiento **real** del sistema. Mockear o parchear en runtime convierte un test en una tautología: comprueba que el mock se comportó como el test dijo que se comportara, no que el código bajo prueba funcione.

**Prohibido en todo el árbol `tests/`:**

- `unittest.mock` (cualquier import: `Mock`, `MagicMock`, `patch`, `PropertyMock`, `create_autospec`, etc.).
- Paquetes externos `mock` y `pytest-mock` (fixture `mocker`).
- Fixture `monkeypatch` de pytest y `pytest.MonkeyPatch`.
- Decoradores `@patch`, `@patch.object`, `@mock.patch`.
- Sustitución manual de atributos en runtime con `setattr(module, "func", lambda ...)` o `module.func = stub`.
- Dependencias en `pyproject.toml` de paquetes de mocking (`pytest-mock`, `mock`, `responses`, `freezegun` cuando se usa para parchear, etc.).

**Cómo escribir tests sin mocks:**

- **Adaptadores reales con fakes / in-memory implementations**. Cuando un test necesita un `DisassemblerInterface`, usar `MockDisassembler` (que es una *implementación* del protocolo, no un mock dinámico de `unittest.mock`) o un fake en memoria que herede del mismo protocolo y devuelva datos controlados.
- **Binarios de prueba en `fixtures/`**. Para tests de pipeline/mutación: fichero ELF/PE/Mach-O mínimo en disco que ejerza el camino que se quiere validar.
- **Inyección de dependencias por constructor**. El SUT (system under test) recibe sus colaboradores como argumentos; el test inyecta implementaciones reales pequeñas en lugar de parchear módulos globales.
- **`tmp_path` / `tmp_path_factory`**. Para tests con I/O, escribir a un directorio temporal real.
- **Subprocesos reales** cuando el código llama a `r2`, `objdump`, etc.: si no hay binario disponible en el runner, el test se marca como `@pytest.mark.integration` y se ejecuta en el entorno que sí lo tiene; nunca se mockea la salida.
- **Test doubles explícitos en `tests/_doubles/`**. Si necesitas una variante de un adaptador para pruebas, vive como clase con nombre (`InMemoryReportSink`, `RecordingPipeline`), no como `Mock()` anónimo.

**Razón:** mocks y monkeypatch enmascaran cambios en la API real, falsean cobertura, y producen tests verdes contra código roto. Cada bug histórico en r2morph causado por divergencia mock/real es el motivo de esta regla. Si un test no se puede escribir sin mockear, es señal de que el diseño está acoplado y necesita refactor — **no** de que la regla deba relajarse.

**Excepción**: ninguna. Si aparece un caso aparentemente irresoluble, se discute y se refactoriza el SUT, no el test.

---

## 5. Tests de regresión obligatorios

Toda **feature nueva**, **bugfix**, **refactor con cambio de comportamiento observable** o **cambio de API pública** debe ir acompañado de al menos un test de regresión en el mismo PR. Sin test, no se mergea.

**Reglas:**

- **Bugfix → test que reproduce el bug**. El test debe fallar contra `main` antes del fix y pasar después. No vale "lo probé a mano". El test bloquea la regresión futura; sin él, el bug volverá.
- **Feature nueva → tests que cubren el camino feliz y al menos los bordes evidentes** (input vacío, input máximo, error path, concurrencia si aplica). Una feature sin tests no se considera entregada.
- **Refactor que cambia comportamiento → test que documenta el nuevo contrato**. Si el refactor es "sin cambio de comportamiento", debe existir cobertura previa que lo demuestre; si no existe, **se añade antes** del refactor (caracterización), no después.
- **Cambio de API pública** (`r2morph/protocols/`, `cli.py`, esquemas de report) → test que ejerce el nuevo contrato y, si procede, test que verifica el manejo del input legado/migración.
- **Los tests viven cerca del código que prueban**: `tests/unit/...`, `tests/integration/...`, `tests/regression/...` según corresponda. Si el bug era de integración, el test es de integración.
- **El commit / PR debe enlazar test ↔ código**: el mensaje (o la descripción del PR) menciona qué test cubre el cambio. Si son varios, se enumeran.
- **Cumplen las reglas de la sección 4**: tests reales, sin mocks ni monkeypatch.

**Regression contracts:**

- Todas las APIs públicas y todos los esquemas de salida (`report_schema.json`, SARIF) son **contratos de regresión**. Cualquier cambio en ellos exige actualizar call sites, fixtures y tests en el mismo PR.
- Antes de refactorizar, **comprobar que hay cobertura del comportamiento actual**. Si no la hay, escribirla primero (caracterización) y commitearla aparte; luego refactorizar.
- Después de cualquier cambio, ejecutar la suite completa y los checks de CI (sección 3). Sin excepciones.

**Prohibido:**

- Mergear un bugfix sin test que lo reproduzca.
- Marcar tests como `xfail`, `skip` o `skipif` para esquivar un fallo legítimo. Si un test es inestable, se arregla la inestabilidad; si el comportamiento cambió a propósito, se actualiza la aserción.
- Borrar tests para "limpiar" sin documentar en el PR por qué la cobertura ya no aplica.

---

## 6. Clean Code (obligatorio)

- **Funciones cortas y con una única responsabilidad**. Si supera ~40 líneas o tiene más de 3 niveles de anidamiento, refactorizar.
- **Nombres descriptivos** para variables, funciones, clases y módulos. Nada de `tmp`, `data`, `x`, `helper2`, salvo en scopes de 2-3 líneas evidentes.
- **Sin código muerto**: ramas inalcanzables, imports no usados, funciones sin callers, parámetros silenciados — se eliminan.
- **Sin comentarios redundantes** que reescriben lo que ya dice el código. Comentar solo el **porqué** cuando no es obvio (un workaround, una invariante oculta, una restricción externa).
- **Sin TODOs / FIXMEs sin issue asociado**. Cada TODO debe enlazar a un ticket; si no hay ticket, no hay TODO — se hace o se documenta como decisión.
- **Sin números mágicos**. Constantes nombradas con su unidad y semántica.
- **Errores explícitos**: excepciones tipadas, mensajes accionables. Nada de `except Exception: pass` ni capturas overbroad sin justificación documentada.
- **Inmutabilidad por defecto**: `frozen=True` en dataclasses cuando aplica, `tuple` antes que `list` mutable compartido, evitar estado global.
- **Formato consistente**: `black` decide; no se discute.

---

## 7. Clean Architecture (obligatorio)

r2morph respeta la separación de capas. Cualquier nuevo módulo debe encajar en esta jerarquía:

```
core/           ← entidades y reglas de dominio (sin dependencias externas)
pipeline/       ← orquestación de casos de uso (depende de core)
mutations/      ← lógica de transformación (depende de core, protocols)
analysis/       ← análisis estático/dinámico (depende de core, protocols)
adapters/       ← adaptadores hacia herramientas externas (r2pipe, lief, frida)
protocols/      ← interfaces / contratos abstractos
platform/       ← detalles específicos de formato (PE, ELF, Mach-O)
reporting/      ← salida (JSON, SARIF, terminal)
cli.py          ← entrada de usuario; sin lógica de dominio
```

Reglas estructurales:

- **Las capas internas (`core`, `protocols`) no importan de capas externas** (`adapters`, `cli`, `reporting`).
- **Depender de abstracciones, no implementaciones**. Los componentes de dominio reciben interfaces (`DisassemblerInterface`, etc.), no clases concretas.
- **Sin ciclos de import** entre módulos. Si los hay, hay un problema de capas.
- **Validación solo en bordes del sistema** (input de CLI, ficheros externos, APIs). El código interno confía en los tipos.
- **Sin abstracciones prematuras**: tres líneas similares no justifican una abstracción. Cuatro casos reales sí.
- **Sin "god objects"**: ninguna clase / función supera ~200 líneas o agrupa responsabilidades no relacionadas.
- **Adaptadores aislados**: cualquier llamada a r2pipe, lief, frida, angr, z3 vive en `adapters/` o `analysis/` con interfaz publicada en `protocols/`. El resto del código no los conoce.
- **CLI sin lógica de dominio**: `cli.py` parsea args y delega; no decide flujos de mutación, no abre binarios directamente.

Antes de añadir un módulo nuevo, responde: ¿en qué capa vive? ¿qué interfaces consume? ¿qué interfaces expone? Si no hay respuesta clara, el diseño no está listo.

---

## 8. Mutaciones agnósticas a la muestra — nada family-specific en producción

r2morph es un motor de mutación de **propósito general**: cualquier `MutationPass`, analizador o adaptador debe aplicar a binarios arbitrarios, no a la muestra concreta que se esté investigando. Código que solo funciona para "este binario" o "esta familia" es un bug, viva en la capa que viva.

- **Sin valores de familia/IOC en rutas de producción.** No hardcodear hosts, URLs, rutas, claves de registro, nombres de mutex/tarea, GUIDs, hashes de API, strings de payload, offsets fijos, duraciones de sleep ni marcadores de control-flow de una muestra concreta dentro de `mutations/`, `pipeline/`, `analysis/`, `adapters/` o `platform/`.
- **Sin ramas sample-specific.** Nada de ramas "solo-para-X-packer" o "solo-para-Y-familia" en lógica de producción, aunque mejoren una regresión real concreta. No pattern-match sobre secuencias de opcodes de un packer concreto para tomar un atajo, ni devolver un valor solo porque una muestra lo espera.
- **Sube el nivel de abstracción.** Si una muestra real expone un seam que falta, implementa el contrato **genérico** más estrecho que explique el comportamiento (semántica de ISA, invariantes de formato PE/ELF/Mach-O, semántica de la API). Si no puedes describir el código nuevo en términos de una spec pública o un contrato documentado, has escrito lógica sample-specific.
- **Los valores de muestra viven en tests y fixtures, nunca en runtime.** Un test de regresión puede afirmar "esta muestra concreta tras el pass X mantiene el CFG equivalente"; el `MutationPass` no puede contener código que solo se dispare para esa familia. Los binarios concretos van en `fixtures/`, los asserts en `tests/`.
- **Paridad de parsers.** No sortear en silencio una estructura PE/ELF/Mach-O malformada que solo produce un packer concreto. O se rechaza explícitamente con un error tipado y una razón anclada al formato, o se arregla el parser para el caso general (cualquier otro binario con la misma forma debe funcionar).
- **Ante la duda, expón el seam.** Si parece un quirk de una muestra, escribe la aserción sample-specific en un test de regresión y abre un follow-up — no incrustes el quirk en el runtime.

---

## 9. Observabilidad y manejo de bytes de muestra

r2morph procesa malware. Los bytes de la muestra son material **semi-sensible** y la salida del proceso debe ser reconstruible desde los logs.

- **Logging estructurado, no `print`.** En rutas de producción se usa el `logging` del proyecto (logger por módulo), nunca `print`/`pprint`/`sys.stderr.write` ad-hoc. `cli.py` es el único que renderiza a terminal, y lo hace a través de `reporting/`.
- **Niveles con semántica.** `error` para violaciones de contrato, `warning` para anomalías recuperables, `info` para eventos de ciclo de vida (apertura de binario, inicio/fin de pass), `debug` para detalle por-evento, nivel más fino para bucles calientes / por-instrucción.
- **Nunca loguear payloads crudos por encima de `debug`.** Bytes de la muestra, buffers desensamblados, contenido de secciones: por encima de `debug` solo hashes, tamaños y previews cortos acotados. Los contratos de `reporting/` (JSON, SARIF) siguen la misma regla — no se vuelcan blobs completos del binario.
- **Sin datos del host del analista en logs ni reports.** No filtrar rutas absolutas del analista, nombre de usuario ni variables de entorno locales a la salida.
- **Contexto en los bordes.** Abrir contexto de log en los adaptadores (`adapters/`, parsers de `platform/`, ejecución de cada pass) para que el comportamiento del pipeline sea reconstruible solo con los logs.

---

## 10. Guardarraíles de retención y memoria

El pipeline puede procesar binarios grandes y muchas muestras en serie. La RAM del host es una **superficie de contrato**, no un detalle de implementación.

- **Sin retención ilimitada.** Cualquier `list`/`dict`/`set` que crezca con eventos de runtime (trackers, acumuladores de report, cachés del pipeline) necesita un cap explícito, política de evicción o presupuesto de bytes. Crecimiento sin cota es un bug.
- **Sin payloads crudos en rutas de tracker/report** salvo que el contrato de salida lo exija de verdad. Preferir resúmenes, hashes, contadores, identificadores estables y previews cortos sobre blobs completos.
- **Sin clonar colecciones completas en rutas calientes.** No copiar trackers/observaciones/reports enteros en el hot path si hay una alternativa que preserve la propiedad; mover los datos hacia delante etapa a etapa.
- **Recursión acotada.** Cualquier interpretación/recorrido recursivo (CFG, estructuras anidadas) aplica un límite global de profundidad antes de la siguiente llamada recursiva.
- **Regresión que prueba la cota.** Si un cambio toca retención de tracker, proyección de report o cachés del pipeline, añade un test que demuestre la nueva cota (cumpliendo §4 y §5).

---

## 11. Política de evolución

- **Sin compatibilidad legacy para features propias.** Cuando una feature, API interna, flag de CLI, campo de report, perfil o adaptador reemplaza a otro más viejo, se elimina la implementación obsoleta, sus docs, tests, fixtures, alias y rutas de fallback en el mismo cambio. No se preserva comportamiento legacy solo porque una interfaz interna antigua existía. La compatibilidad **solo** es válida cuando modela contratos externos públicos que r2morph debe soportar: formatos PE/ELF/Mach-O, semántica de ISA, esquemas de report versionados públicamente (`report_schema.json`, SARIF).
- **El código es propio.** Herramientas, papers y proyectos open-source externos pueden inspirar el diseño, pero el código que se commitea es original y alineado con la arquitectura de r2morph. No se porta, copia ni transliterar implementaciones de terceros.
- **Sin nombres de herramientas externas en el código.** No nombrar otras herramientas o productos en identificadores de producción, comentarios, nombres de test/fixture, salida al usuario, reports generados ni labels de comportamiento. Se describe el comportamiento por el contrato genérico implementado, no por la herramienta que lo inspiró. Si el tooling del repo debe invocar un ejecutable externo concreto (`r2`, `objdump`), esa referencia vive en scripts/configuración o en el adaptador aislado de `adapters/`, no esparcida por la lógica de dominio.

---

## 12. Disciplina de comunicación

- **No asumas. No escondas la confusión. Expón los tradeoffs.** Cuando una petición es ambigua o tomas una decisión no obvia, nombra el tradeoff y deja redirigir — no elijas un camino en silencio y lo presentes como decidido.
- **Levanta el estado inesperado antes de trabajar alrededor.** Si aparecen ficheros, ramas o estado conflictivo no familiares a mitad de tarea, se reporta antes de seguir, no se parchea por encima.

---

## 13. Disciplina de testing (complementa §4 y §5)

Además de "tests reales sin mocks" (§4) y "regresión obligatoria" (§5):

- **Naming**: `test_<sujeto>_<escenario>_<resultado_esperado>`. Nada de `test_works`, `test_basic`, `test_1`.
- **Una sola aserción lógica por test.** Un test debe fallar por una única razón. Si un escenario verifica varias invariantes no relacionadas, se parte en tests distintos en vez de encadenar asserts.
- **Layering explícito**: unit junto al código (`tests/unit/`), integración en `tests/integration/`, regresión en `tests/regression/`, contratos de API/esquema en sus ficheros nombrados.
- **Fixtures sobre corpus.** Las suites por defecto (unit/integration/regresión) dependen de fixtures sintéticos o generados localmente, no de un corpus de malware local. Si una regresión necesita una muestra externa real, es **opt-in** y queda fuera de la suite por defecto: solo falla en cerrado cuando el caller pasa la ruta de la muestra explícitamente; nunca hace que el árbol normal dependa del layout del corpus local.

---

## 14. Watchlist de descomposición

El límite de §6 (~40 líneas/función) y §7 (~200 líneas/clase, sin god-objects) se complementa con un objetivo a nivel de **fichero**:

- **Objetivo de fichero <500 líneas (responsabilidad única); límite duro 800.** Un fichero que cruza 500 líneas es un punto de extensión caliente: añade comportamiento nuevo en un sub-módulo hermano en vez de seguir apilando en el agregador. Un fichero >800 líneas debe descomponerse **antes** de cualquier otro cambio sobre él (no se permiten ediciones append-only sobre un fichero que viola el límite duro).
- **Excepción**: tablas de dispatch exhaustivas (un único `match`/`dict` sobre un conjunto cerrado que delega a helpers por-variante, sin lógica de dominio en el cuerpo) pueden exceder el límite.
- **Upkeep del mapa**: si un refactor renombra un módulo o parte un fichero en un directorio de sub-módulos, se actualiza el mapa de arquitectura (§7 y §17) en el mismo commit. El contrato solo sirve si rastrea la realidad.

---

## 15. Rendimiento — medir antes de refactorizar

- **Profile antes de optimizar.** Eliminar `.copy()`, cambiar algoritmos de hash o reescribir "esto parece caro" sin un profile que lo respalde está prohibido.
- **Umbral**: por debajo de ~2% de self-time acumulado no se procede con un refactor por rendimiento; se cierra la investigación en una nota datada y se sigue. Estima también el ahorro real esperado.
- **Artefactos**: reports de profiling datados (`YYYY-MM-DD-<tema>.md`) junto a los fixtures usados para generarlos, en una carpeta dedicada (p. ej. `docs/profiling/`). Tras cada cambio se anexan los deltas antes/después al mismo report.
- **Re-validación**: tras un cambio de rendimiento, re-ejecutar la suite y los checks de §3 antes de dar el trabajo por terminado.

---

## 16. UX de un solo binario — inferencia automática

El camino normal de mutación/análisis debe requerir solo la **ruta del binario**. El usuario no tiene por qué conocer arquitectura, entrypoint, formato, perfil de mutación ni presupuesto para obtener el mejor resultado disponible.

- **Inferir por defecto.** Preferir metadata del loader, headers PE/ELF/Mach-O, imports y heurísticas genéricas sobre exigir flags de CLI.
- **Los argumentos extra son overrides, no prerequisitos.** Los switches de CLI existen para debug, reproducción de regresiones e investigación, pero la ejecución ordinaria no depende de pasar un montón de opciones.
- **La automatización ausente es un gap de producto.** Si una muestra solo corre cuando un humano aporta knobs concretos, se captura el seam genérico que falta y se mueve ese conocimiento a la configuración automática o a un follow-up. No se normaliza "dile al usuario qué flags pasar" como fix final.
- **Inferencia agnóstica a la muestra.** Los argumentos/perfiles auto-seleccionados salen de contratos públicos de formato/API o de heurísticas amplias, nunca de hechos de una familia concreta (§8).

---

## 17. Mapa de arquitectura y refactor guardrails

El mapa de capas de §7 es el **contrato vivo**. Reglas para mantenerlo útil:

- **Seams que no deben crecer.** `protocols/` es la SPI de infraestructura: mantenla enfocada en intención, sin filtrar mecanismos concretos de r2pipe/lief/frida. `cli.py` es composición + parseo; no mueve política de dominio hacia dentro. Los adaptadores de `adapters/` no filtran tipos de la herramienta externa hacia `core`/`pipeline`.
- **Anti-corruption en los bordes.** La traducción de tipos de herramienta externa (r2pipe/lief/angr/z3) a DTOs de dominio vive en el adaptador, no esparcida por los consumidores.
- **Sin ciclos** entre módulos (ya en §7); cualquier ciclo es un problema de capas que se arregla, no se rodea.
- **Upkeep**: cualquier cambio que renombre una capa, mueva un fichero clave o cambie un contrato de `protocols/` actualiza este mapa y el de §7 en el mismo commit.

---

## 18. Convenciones de commits

- **Mensaje claro, en imperativo, describiendo el *qué* y el *porqué***. Nada de "wip", "fix", "update", "changes". Si el cambio toca varias áreas, separar en commits distintos.
- **Un commit, un cambio lógico**. No mezclar refactor + feature + bugfix en un solo commit.
- **El commit que introduce un fix o feature referencia el test que lo cubre** (sección 5). Si el test va en otro commit del mismo PR, mencionarlo.

**Prohibido añadir co-autores artificiales en los commits.** En particular:

- **Nada de `Co-Authored-By: Claude ...`**, ni `Co-Authored-By: <cualquier asistente IA>`, ni trailers tipo `Generated-by:`, `Assisted-by:`, `🤖 Generated with Claude Code`, ni enlaces promocionales en el cuerpo del commit.
- El asistente IA **no es co-autor**: es una herramienta. El autor del commit es la persona que firma el PR y se responsabiliza del cambio.
- Co-autores reales (otra persona humana que contribuyó al cambio) sí se añaden con `Co-Authored-By: Nombre <email>` cuando aplica.
- **No firmar commits con identidades distintas** a la del autor real ni cambiar `user.name` / `user.email` para enmascarar autoría.

Esta regla aplica también a PRs generados con asistencia IA: el cuerpo del commit/PR describe el cambio técnicamente, sin frases promocionales ni atribuciones a herramientas.

---

## 19. Cumplimiento

- Estas reglas se verifican en CI. Un PR que rompa cualquiera de ellas **no se mergea**.
- El que abre el PR es responsable de pasar todos los checks localmente antes de pedir review.
- Cualquier excepción a estas reglas se documenta en este fichero bajo "Excepciones aprobadas" con justificación, fecha y owner.

## Excepciones aprobadas

### EX-001 — mypy `ignore_missing_imports` para C-extensions sin stubs

- **Ámbito**: `[[tool.mypy.overrides]]` en `pyproject.toml`, acotado a estos módulos: `angr`, `archinfo`, `capstone`, `claripy`, `frida`, `keystone`, `lief`, `miasm`, `psutil`, `qiling`, `r2pipe`, `unicorn`, `z3`.
- **Justificación técnica**: estas librerías son extensiones C (o wrappers de ellas) que no publican stubs `py.typed` ni paquetes `types-*` mantenidos. No hay forma de tipar sus símbolos importados sin escribir stubs internos completos — esfuerzo desproporcionado para el valor que aportaría.
- **Alternativas evaluadas**:
  1. `types-*` en PyPI → no existen para estas libs.
  2. Stubs internos en `stubs/` → coste alto, mantenimiento por cada release upstream.
  3. `cast(Any, ...)` en cada uso → contamina el código con casts a lo largo de cientos de llamadas.
- **Mitigaciones**:
  - El override está **acotado por módulo**, no es global.
  - El resto de `strict = true` permanece activo: cualquier función que use estos módulos debe tipar sus propios parámetros y retornos.
  - Revisar en cada release: si upstream publica `py.typed`, eliminar de la lista.
- **Owner**: Marc Rivero.
- **Fecha**: 2026-05-15.
- **Commit**: pendiente (junto a la reescritura de `pyproject.toml`).

### EX-002 — `filterwarnings` ignore acotado al `DeprecationWarning` de ctypes de `cle`

- **Ámbito**: una única entrada en `[tool.pytest.ini_options] filterwarnings` de `pyproject.toml`:
  `"ignore:Due to '_pack_', the .* Structure will use memory layout compatible with MSVC:DeprecationWarning"`.
  El default sigue siendo `"error"`; este ignore es el último filtro y solo gana para ese mensaje exacto.
- **Justificación técnica**: al hacer `import angr` se importa transitivamente `cle`, cuyo módulo `cle/backends/coff.py` define subclases de `ctypes.LittleEndianStructure` con `_pack_` pero sin `_layout_`. En Python 3.14 `ctypes` emite un `DeprecationWarning` en tiempo de import (antes de que se ejecute ningún test). No es código de r2morph y no hay forma de evitarlo desde r2morph: el warning se dispara dentro de `cle` al crear la clase. Bajo el `pytest -W error` obligatorio (sección 3) esto abortaba la colección de 8 módulos de test que usan symbolic/angr.
- **Alternativas evaluadas**:
  1. Subir `angr`+`cle` → **verificado infactible**: `cle` 9.2.215 (última versión publicada) emite el MISMO warning, y `angr` 9.2.215 usa sintaxis PEP 695 que rompe `mypy r2morph` bajo el `python_version` del proyecto. Revertido a 9.2.195.
  2. Parchear `cle` desde r2morph → modificar código de un tercero instalado; frágil y prohibido.
  3. Fijar Python <3.14 → el deprecation solo existe en 3.14+, pero degradar el runtime soportado del proyecto por una lib de terceros es peor trade-off que un ignore ultra-acotado.
  4. `import` lazy de angr (hecho, commit `0919ce4`) → reduce el blast radius (no se importa angr salvo que se use symbolic) pero NO elimina el warning cuando symbolic sí se ejercita.
- **Mitigaciones**:
  - El filtro está **acotado por mensaje y categoría** (`DeprecationWarning`), no es un `ignore::DeprecationWarning` global. Cualquier otro `DeprecationWarning` (incluido cualquiera de código r2morph) sigue siendo `error`.
  - `import` de angr ya es lazy (EX-002 solo cubre el residuo inevitable cuando symbolic se usa de verdad).
  - Revisar en cada release de `cle`/Python: si `cle` añade `_layout_` o se sube el suelo de Python, eliminar esta entrada y los 8 módulos deben seguir verdes sin ella.
- **Owner**: Marc Rivero.
- **Fecha**: 2026-05-16.
- **Commit**: pendiente (commit que añade el filtro EX-002 en `pyproject.toml`).

### EX-003 — `noqa: BLE001` acotado a la frontera de aislamiento de fallos del pipeline

- **Ámbito**: una única línea, el `except Exception as e:` del bucle por-pass en `r2morph/pipeline/pipeline.py` (método `Pipeline.run`, el `try` que envuelve la ejecución completa de un `MutationPass`: apply + validación + record). El `# noqa: BLE001` está acotado a esa línea; el resto del fichero y del proyecto sigue sujeto a `BLE` sin excepción.
- **Justificación técnica**: los `MutationPass` son un **punto de extensión abierto** (26 módulos de pass: nop, substitute, register, control_flow_flattening, code_virtualization, api_hashing, …) que operan sobre el binario a través de `r2pipe` (subproceso → `BrokenPipeError`/`OSError`/`TimeoutExpired`), `keystone`/`capstone` (clases de excepción propias), `lief`, y `struct` (`struct.error`), además de `RuntimeError`/`ValueError`/`KeyError`/`IndexError` internos. El conjunto de excepciones no está centralizado ni acotado y crece con cada pass o versión de dependencia. Este `except` **es** la frontera de aislamiento de fallos del pipeline: un pass que falle debe quedar contenido (log con nombre del pass + rollback al checkpoint de sesión + registro estructurado del error + respeto de `rollback_policy == "fail-fast"` que re-lanza + `finally` que limpia runtime) y el pipeline debe continuar con los passes restantes. No es un swallow silencioso (el patrón prohibido por §6 es `except Exception: pass`; aquí se loguea, se registra y se re-lanza condicionalmente). `BaseException` **no** se captura: `KeyboardInterrupt`/`SystemExit` se propagan correctamente.
- **Alternativas evaluadas**:
  1. Acotar a una tupla de tipos concretos → **regresión de corrección**: por diseño es un conjunto abierto; un tipo no enumerado escaparía y abortaría todo el pipeline, rompiendo el contrato de rollback+continue y los tests que lo verifican. No es un fix, es trasladar un fallo de lint a un bug.
  2. Extraer la ejecución del pass a un helper que devuelva `Result`/error → el `except Exception` sigue existiendo dentro del helper; `BLE001` se dispara igual. Solo mueve el problema.
  3. `ignore` global de `BLE001` en `[tool.ruff.lint]` o `per-file-ignores` → explícitamente prohibido por §1 (peor que un noqa acotado a una línea).
- **Mitigaciones**:
  - Acotado a **una línea**; cualquier otro `except` ancho del proyecto sigue siendo error de `BLE`.
  - El handler es observable y accionable: log con nombre de pass, rollback determinista al checkpoint, error estructurado en `pass_results`, y `raise` en modo `fail-fast`.
  - `BaseException` fuera de alcance (no se traga `KeyboardInterrupt`/`SystemExit`).
  - Revisar en cada release: si el conjunto de excepciones de los passes llegara a centralizarse en una jerarquía propia (p. ej. una `MutationPassError` base que todos los passes garanticen), acotar el `except` a esa base y eliminar EX-003.
- **Owner**: Marc Rivero.
- **Fecha**: 2026-05-17.
- **Commit**: pendiente (commit que documenta EX-003 y acota el comentario inline en `pipeline.py`).
