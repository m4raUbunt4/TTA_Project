Especificación del Proyecto: Threat-Triage-Automator (TTA)
1. Objetivo Estratégico
Desarrollar una herramienta CLI Threat-Triage-Automator (para ejecución manual diaria en entorno de desarrollo/análisis) que consolide inteligencia de amenazas de múltiples fuentes (OTX, CVE/NVD, VirusTotal), filtre por relevancia al contexto empresarial de Latinoamérica y el sector bancario, y utilice Inteligencia Artificial (LLM) para generar un reporte ejecutivo + técnico con guías de acción (Playbooks) concretas para equipos de seguridad, threat hunting y pentesting.
2. Alcance (MVP - Producto Mínimo Viable)
Fuentes de datos (Fase Inicial)
·	AlienVault OTX (Pulses de las últimas 24 horas).
·	NVD / NIST API (Detalles técnicos de CVEs asociados).
·	VirusTotal API (Enriquecimiento de reputación de IoCs encontrados).
Capacidades del Core
·	Filtrado automatizado multi-criterio.
·	Procesamiento de texto no estructurado mediante IA para síntesis de contexto.
·	Generación de reportes limpios y listos para consumo técnico/ejecutivo.

3. Criterios de Filtrado
Para maximizar la relevancia y reducir el ruido, las amenazas recolectadas pasarán por un triple tamiz. Debido a que las fuentes globales publican mayoritariamente en inglés, las palabras clave se validarán en ambos idiomas o mediante la interpretación semántica de la IA:
Criterio	Umbral / Condición	Notas / Ejemplos
Severidad Técnica	CVSS Score \geq 7.8 (Alto/Crítico)	Filtro duro inicial para CVEs.
Filtro Geográfico / Sector	Coincidencia en etiquetas o descripción	méxico, mexico, latam, banco, bank, finance, financiero.
Filtro Tecnológico	Stack de infraestructura crítica empresarial	vpn, fortinet, cisco, active directory, ransomware, phishing.


4. Estructura del Reporte de Salida (TAA_Report_YYYYMMDD_HHMM.md)
El reporte se estructurará en Markdown y cada amenaza validada contendrá cuatro secciones fijas, donde las secciones 4.2 y 4.4 serán redactadas dinámicamente por la IA:
4.1 Resumen Ejecutivo (Técnico)
·	Identificador (CVE o ID de OTX Pulse).
·	Nombre de la amenaza / Vulnerabilidad.
·	Severidad (CVSS) y fuentes de origen.
4.2 Análisis de Contexto Empresarial (Potenciado por IA)
·	¿A qué tipo de organización o vertical ataca típicamente?
·	¿Existe motivación geopolítica, fraude financiero o campaña activa en LatAm?
·	Grupo de actores detrás de la amenaza (APT, bandas de Ransomware), si se conoce.
4.3 Indicadores y Datos Técnicos
·	Lista de IoCs asociados (IPs, Dominios, Hashes) validados con reputación en VirusTotal.
·	Vector de ataque (ej. Explotación perimetral, Ingeniería Social).
4.4 Guía de Acción Inmediata / Playbook (Potenciado por IA)
·	Para Pentesting/Validación: Pasos lógicos o herramientas open-source (ej. Nuclei, CURL con payloads específicos) para verificar de forma segura si somos vulnerables.
·	Para Threat Hunting: Qué buscar en los logs (Firewall, EDR, SIEM).
·	Para Mitigación: Parche oficial o contramedida táctica alternativa.

5. Restricciones Técnicas y Entorno
Lenguaje: Python 3.9+ (Ejecución local en terminal de Mac).
Motor de IA: Google Gemini API (gestionado vía Google AI Studio).
Gestión de Secretos: Uso de python-dotenv para cargar GEMINI_API_KEY, OTX_API_KEY y VT_API_KEY desde un archivo local .env no versionado.
Entorno de ejecución: CLI local. Los resultados se guardan como archivos Markdown con timestamp (TAA_Report_YYYYMMDD_HHMM.md).
6. Criterios de Aceptación (DoD - Definition of Done)
·	El script se ejecuta de punta a punta sin errores en Google Colab.
·	Conecta exitosamente a las APIs usando los Secrets del entorno.
·	Filtra de forma efectiva los datos correlacionando severidad y palabras clave (inglés/español).
·	La IA procesa correctamente los payloads de texto e inyecta las secciones analíticas y las guías de pruebas tácticas.
·	Genera un archivo .md estructurado descargable directamente desde el panel de archivos de Colab.

7. Roadmap de Desarrollo (Por Fases)
Fase	Entregable	Estado
Fase 0	Configuración de Secrets en Colab y estructura base del script.	Pendiente
Fase 1	Extracción desde AlienVault OTX, aplicación de filtros duros y esqueleto del reporte.	Pendiente
Fase 2	Conexión con NVD/CVE e integración del módulo de IA para análisis y Playbooks.	Pendiente
Fase 3	Integración con VirusTotal para el enriquecimiento y reputación de IoCs.	Pendiente
Fase 4	Pruebas de integración final, optimización de Prompts de IA y refinamiento del formato.	Pendiente

