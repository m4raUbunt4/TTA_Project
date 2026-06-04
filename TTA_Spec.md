# Especificación del Proyecto: Threat-Triage-Automator (TTA)

## 1. Objetivo Estratégico

Desarrollar una herramienta CLI Threat-Triage-Automator (para ejecución manual
diaria en entorno de desarrollo/análisis) que consolide inteligencia de amenazas
de múltiples fuentes (OTX, CVE/NVD, MITRE, VirusTotal y feeds RSS especializados),
filtre por relevancia al contexto empresarial de Latinoamérica y el sector bancario,
y utilice Inteligencia Artificial (LLM) para generar un reporte ejecutivo + técnico
con guías de acción (Playbooks) concretas para equipos de seguridad, threat hunting
y pentesting.

---

## 2. Alcance (MVP - Producto Mínimo Viable)

### Fuentes de datos (Fase Inicial)

| Fuente | Tipo | Endpoint / URL de referencia |
| :--- | :--- | :--- |
| **AlienVault OTX** | API REST | `https://otx.alienvault.com/api/v1/pulses/subscribed` |
| **NVD / NIST** | API REST | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| **MITRE CVE** | API REST / RSS | `https://cveawg.mitre.org/api/cve` · Feed: `https://www.cve.org/feeds/` |
| **VirusTotal** | API REST | `https://www.virustotal.com/api/v3/` |
| **RSS - US-CERT CISA** | Feed RSS | `https://www.cisa.gov/cybersecurity-advisories/all.xml` |
| **RSS - The Hacker News** | Feed RSS | `https://feeds.feedburner.com/TheHackersNews` |
| **RSS - Krebs on Security** | Feed RSS | `https://krebsonsecurity.com/feed/` |
| **RSS - Cybersecurity News** | Feed RSS | `https://cybersecuritynews.com/feed/` |
| **RSS - Hacking Articles** | Feed RSS | `https://www.hackingarticles.in/feed/` |
| **RSS - Kaspersky Securelist** | Feed RSS | `https://securelist.com/feed/` |
| **RSS - Cisco Talos Intelligence** | Feed RSS | `https://blog.talosintelligence.com/feeds/posts/default` |
| **RSS - Palo Alto Unit 42** | Feed RSS | `https://unit42.paloaltonetworks.com/feed/` |
| **RSS - ESET WeLiveSecurity** | Feed RSS | `https://www.welivesecurity.com/en/rss/feed/` |
| **RSS - Microsoft Security Blog** | Feed RSS | `https://www.microsoft.com/en-us/security/blog/feed/` |
| **RSS - CrowdStrike Blog** | Feed RSS | `https://www.crowdstrike.com/blog/feed/` |
| **RSS - Mandiant (Google Cloud)** | Feed RSS | `https://www.mandiant.com/resources/blog/rss.xml` |
| **RSS - Sophos News** | Feed RSS | `https://news.sophos.com/en-us/feed/` |
| **RSS - Check Point Research** | Feed RSS | `https://research.checkpoint.com/feed/` |
| **RSS - Trend Micro Research** | Feed RSS | `https://feeds.trendmicro.com/TrendMicroResearch` |

> **Nota sobre MITRE vs NVD:** NVD es la fuente primaria para obtener el score CVSS
> y el análisis técnico. MITRE CVE se consultará como fuente autoritativa del
> identificador y como fallback para metadata adicional cuando NVD no tenga el
> registro completo (frecuente en zero-days recientes).

> **Nota sobre feeds RSS:** Los feeds se consumirán como fuente de contexto
> complementaria y enriquecimiento narrativo para el módulo de IA. No generan IoCs
> directamente, pero aportan señales de campañas activas que pueden correlacionarse
> con los datos de OTX y NVD. Los feeds de vendors (Talos, Unit 42, Mandiant, ESET)
> son prioritarios por su cobertura técnica y su seguimiento de APTs activos en LatAm.

### Capacidades del Core
- Filtrado automatizado multi-criterio.
- Procesamiento de texto no estructurado mediante IA para síntesis de contexto.
- Generación de reportes limpios y listos para consumo técnico/ejecutivo.

---

## 3. Criterios de Filtrado

Para maximizar la relevancia y reducir el ruido, las amenazas recolectadas pasarán
por un triple tamiz aplicado con lógica **AND** entre criterios (una amenaza debe
superar los tres para incluirse en el reporte). Debido a que las fuentes globales
publican mayoritariamente en inglés, las palabras clave se validarán en ambos
idiomas o mediante interpretación semántica de la IA.

> **Nota sobre CVEs sin score:** Los CVEs sin score CVSS asignado (zero-days
> recientes) serán incluidos de forma provisional con una etiqueta `CVSS: N/A`
> para revisión manual, sin ser descartados automáticamente.

| Criterio | Umbral / Condición | Notas / Ejemplos |
| :--- | :--- | :--- |
| **Severidad Técnica** | CVSS Score ≥ 7.8 (Alto/Crítico) o `N/A` | Filtro duro inicial para CVEs. |
| **Filtro Geográfico / Sector** | Coincidencia en etiquetas o descripción | `méxico`, `mexico`, `latam`, `banco`, `bank`, `finance`, `financiero`. |
| **Filtro Tecnológico** | Stack de infraestructura crítica empresarial | `vpn`, `fortinet`, `cisco`, `active directory`, `ransomware`, `phishing`. |

---

## 4. Arquitectura y Flujo de Datos

El script se estructura en módulos independientes que se ejecutan secuencialmente:

```
[OTX API]      ─┐
[NVD API]      ─┤
[MITRE API]    ─┼──► Módulo de Recolección ──► Módulo de Filtrado ──► Módulo de IA ──► Generador de Reporte (.md)
[VT API]       ─┤
[Feeds RSS x15]─┘
```

| Módulo | Responsabilidad |
| :--- | :--- |
| **Recolección** | Consulta las APIs y feeds RSS externos, normaliza la respuesta a un formato interno común. |
| **Filtrado** | Aplica el triple tamiz (sección 3) y descarta amenazas irrelevantes. |
| **IA / LLM** | Recibe el contexto de cada amenaza filtrada y genera las secciones analíticas. |
| **Generador** | Ensambla el reporte final en Markdown con timestamp y lo escribe en disco. |

Si una API externa o feed falla durante la ejecución, el módulo de recolección
registra el error en un log y **continúa con las fuentes disponibles**, indicando
en el reporte qué fuentes no pudieron consultarse.

---

## 5. Estructura del Reporte de Salida (`TTA_Report_YYYYMMDD_HHMM.md`)

El reporte se estructurará en Markdown y cada amenaza validada contendrá cuatro
secciones fijas, donde las secciones **5.2** y **5.4** serán redactadas
dinámicamente por la IA:

### 5.1 Resumen Ejecutivo (Técnico)
- Identificador (CVE o ID de OTX Pulse).
- Nombre de la amenaza / Vulnerabilidad.
- Severidad (CVSS) y fuentes de origen.

### 5.2 Análisis de Contexto Empresarial (Potenciado por IA)
- ¿A qué tipo de organización o vertical ataca típicamente?
- ¿Existe motivación geopolítica, fraude financiero o campaña activa en LatAm?
- Grupo de actores detrás de la amenaza (APT, bandas de Ransomware), si se conoce.

### 5.3 Indicadores y Datos Técnicos
- Lista de IoCs asociados (IPs, Dominios, Hashes) validados con reputación en VirusTotal.
- Vector de ataque (ej. Explotación perimetral, Ingeniería Social).

### 5.4 Guía de Acción Inmediata / Playbook (Potenciado por IA)
- **Para Pentesting/Validación:** Pasos lógicos o herramientas open-source
  (ej. *Nuclei*, *CURL* con payloads específicos) para verificar de forma
  segura si somos vulnerables.
- **Para Threat Hunting:** Qué buscar en los logs (Firewall, EDR, SIEM).
- **Para Mitigación:** Parche oficial o contramedida táctica alternativa.

---

## 6. Restricciones Técnicas y Entorno

| Elemento | Detalle |
| :--- | :--- |
| **Lenguaje** | Python 3.9+ |
| **Entorno de ejecución** | CLI local (macOS). Script principal: `tta.py` |
| **Motor LLM** | Por definir. La integración se abstraerá en un módulo independiente (`llm_client.py`) para facilitar el cambio de proveedor sin afectar el resto del pipeline. |
| **Gestión de secretos** | Las API Keys y credenciales se inyectan como variables de entorno mediante un script wrapper en Bash (`run_tta.sh`), **nunca hardcodeadas en el código Python**. |
| **Control de versiones** | GitLab. El archivo `.env` y `run_tta.sh` están incluidos en `.gitignore`. El repositorio incluirá un `run_tta.sh.example` con las variables requeridas sin valores. |
| **Rate Limits** | Cada módulo respetará los límites de su API: OTX (10k req/día), NVD (5 req/30s sin key · 50 req/30s con key), VT (según tier). |
| **Dependencias** | Gestionadas mediante `requirements.txt`. Librerías base: `requests`, `feedparser`, y el SDK del proveedor LLM a definir. |
| **Output** | Archivos `.md` con timestamp guardados en el directorio `/reports` del proyecto. |

### Estructura del script wrapper (`run_tta.sh`)

```bash
#!/usr/bin/env bash
# run_tta.sh — NO versionar con valores reales. Ver run_tta.sh.example
export OTX_API_KEY="tu_key_aqui"
export VT_API_KEY="tu_key_aqui"
export LLM_API_KEY="tu_key_aqui"

python3 tta.py
```

---

## 7. Criterios de Aceptación (DoD - Definition of Done)

- [ ] El script `tta.py` se ejecuta de punta a punta sin errores invocándolo desde `run_tta.sh`.
- [ ] Conecta exitosamente a las tres APIs y consume los 15 feeds RSS usando las variables de entorno inyectadas por el wrapper.
- [ ] De un dataset de prueba de 50 pulsos OTX, retiene únicamente los que cumplen el triple filtro y descarta el resto correctamente.
- [ ] Si una API o feed falla, el script continúa con las fuentes restantes y registra el error sin abortar la ejecución.
- [ ] La IA procesa correctamente los payloads de texto e inyecta las secciones analíticas y las guías de pruebas tácticas.
- [ ] Genera un archivo `TTA_Report_YYYYMMDD_HHMM.md` estructurado en el directorio `/reports`.
- [ ] El pipeline completo finaliza en menos de 3 minutos procesando hasta 20 amenazas filtradas.
- [ ] El repositorio en GitLab no contiene ningún secreto o credencial en texto plano en ningún commit.

---

## 8. Roadmap de Desarrollo (Por Fases)

| Fase | Entregable | Estado |
| :--- | :--- | :--- |
| **Fase 0** | Estructura base del repositorio GitLab, `.gitignore`, `run_tta.sh.example` y esqueleto modular del script. | Pendiente |
| **Fase 1** | Extracción desde AlienVault OTX, consumo de feeds RSS, aplicación de filtros duros y esqueleto del reporte. | Pendiente |
| **Fase 2** | Conexión con NVD/NIST y MITRE CVE, integración del módulo LLM (`llm_client.py`) para análisis y Playbooks. | Pendiente |
| **Fase 3** | Integración con VirusTotal para enriquecimiento y reputación de IoCs. | Pendiente |
| **Fase 4** | Pruebas de integración final, optimización de prompts y refinamiento del formato del reporte. | Pendiente |
