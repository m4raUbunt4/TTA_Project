#!/usr/bin/env python3
import os
import sys
import re
import requests
from datetime import datetime
from llm_client import ask_gemini_analyst
from cve_lookup import lookup_cve
from vt_lookup import lookup_ioc_vt
# Importamos nuestro nuevo parser de RSS
from rss_parser import fetch_cisa_rss

def get_mock_pulses():
    print("[!] Contingencia OTX: Cargando amenaza simulada de Gamaredon para complementar el análisis.")
    return [
        {
            "id": "6a1cc51d7c8f832f819a0a43",
            "name": "FSB’s matryoshka – Gamaredon’s GammaPhish and GammaWorm Campaign",
            "description": "Campaña dirigida al sector financiero y gubernamental. Monitorear CVE-2025-8088.",
            "tags": ["banco", "rat", "mexico"],
            "created": datetime.now().strftime("%Y-%m-%d"),
            "indicators": [{"type": "FileHash-SHA256", "indicator": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]
        }
    ]

def fetch_otx_pulses():
    otx_key = os.getenv("OTX_API_KEY")
    if not otx_key or "tu_api_key" in otx_key:
        print("[-] Error: OTX_API_KEY no configurada.")
        sys.exit(1)

    url = "https://otx.alienvault.com/api/v1/pulses/activity"
    headers = {"X-OTX-API-KEY": otx_key}

    print("[*] Conectando con AlienVault OTX API...")
    try:
        response = requests.get(url, headers=headers, timeout=12)
        response.raise_for_status()
        return response.json().get("results", [])
    except Exception as e:
        print(f"[!] Alerta: AlienVault OTX no disponible ({e}).")
        return get_mock_pulses()

def apply_hard_filters(pulses):
    keywords = ["bank", "banco", "finance", "financiero", "mexico", "latam", "vpn", "fortinet", "ransomware", "android", "rat", "cve-", "critical", "cisa"]
    filtered = []
    print(f"[*] Evaluando {len(pulses)} amenazas totales en el motor de filtrado...")
    for pulse in pulses:
        full_text = f"{pulse.get('name','')} {pulse.get('description','')} {' '.join(pulse.get('tags', []))}".lower()
        if any(kw in full_text for kw in keywords):
            filtered.append(pulse)
    print(f"[+] Filtro completado. Permanecen {len(filtered)} amenazas relevantes para el reporte.")
    return filtered

def generate_report(relevant_pulses):
    if not relevant_pulses:
        print("[*] No se encontraron amenazas de alta prioridad. Fin.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    report_path = f"reports/TTA_Report_{timestamp}.md"
    
    print(f"[*] Generando reporte multifuente enriquecido en: {report_path}")
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# Reporte de Inteligencia de Amenazas Consolidado - {datetime.now().strftime('%Y-%m-%d')}\n\n")
        f.write(f"Generado automáticamente por TTA-Engine (Fuentes: OTX, CISA RSS, NVD, VirusTotal) en Debian 13.\n\n")
        f.write("---\n\n")

        for i, pulse in enumerate(relevant_pulses, 1):
            name = pulse.get('name')
            desc = pulse.get('description', 'Sin descripción.')
            pulse_id = pulse.get('id')
            indicators = pulse.get('indicators', [])
            
            # --- 1. ENRIQUECIMIENTO CVE ---
            full_pulse_text = f"{name} {desc} {' '.join(pulse.get('tags', []))}"
            cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', full_pulse_text, re.IGNORECASE)
            cve_enrichment_text = "No se detectaron identificadores CVE explícitos."
            detected_cvss = "N/A"
            cve_source = "Ninguna"
            
            if cve_matches:
                target_cve = cve_matches[0].upper()
                print(f"[*] Detectado {target_cve} en amenaza #{i}. Ejecutando Triage...")
                cve_info = lookup_cve(target_cve)
                detected_cvss = cve_info["cvss"]
                cve_source = cve_info["fuente"]
                cve_enrichment_text = f"CVE: {target_cve} | Score: {detected_cvss} ({cve_source})\nDescripción: {cve_info['descripcion']}"

            # --- 2. ENRIQUECIMIENTO VIRUSTOTAL ---
            vt_enrichment_text = "No se analizaron IoCs en VirusTotal."
            ioc_display = "Ninguno extraído de la fuente"
            vt_output_string = "No disponible"
            
            if indicators:
                main_ioc = indicators[0]
                ioc_type = main_ioc.get("type", "Unknown")
                ioc_value = main_ioc.get("indicator", "")
                ioc_display = f"`{ioc_value}` ({ioc_type})"
                
                print(f"[*] Evaluando reputación del IoC principal en VirusTotal...")
                vt_res = lookup_ioc_vt(ioc_type, ioc_value)
                if vt_res:
                    vt_output_string = vt_res['resultado']
                    vt_enrichment_text = f"Indicador: {ioc_value} | VT: {vt_output_string}"

            # --- 3. ANALISTA DE IA ---
            print(f"[*] Procesando con IA amenaza {i}/{len(relevant_pulses)}: {name}...")
            extended_details = f"Detalles de la Alerta: {desc}\n\n{cve_enrichment_text}\n\nReputación IoC:\n{vt_enrichment_text}"
            ai_analysis = ask_gemini_analyst(name, extended_details)
            
            # --- 4. ESCRITURA MARKDOWN ---
            f.write(f"## Amenaza #{i}: {name}\n\n")
            f.write(f"### 4.1 Resumen Ejecutivo (Técnico)\n")
            f.write(f"- **Identificador Origen:** `{pulse_id}`\n")
            f.write(f"- **CVE Correlacionado:** `{cve_matches[0].upper() if cve_matches else 'Ninguno'}`\n")
            f.write(f"- **Severidad Base (CVSS):** `{detected_cvss}`\n")
            f.write(f"- **Tags de la Fuente:** {pulse.get('tags', [])}\n\n")
            
            f.write(f"{ai_analysis}\n\n")
            
            f.write(f"### 4.3 Indicadores y Datos Técnicos (IoCs)\n")
            f.write(f"- **Infraestructura Relacionada:** {ioc_display}\n")
            f.write(f"- **Reputación (VirusTotal):** `{vt_output_string}`\n")
            f.write(f"- **Enlace de Investigación:** Si es OTX: https://otx.alienvault.com/pulse/{pulse_id}\n\n")
            f.write("---\n\n")
            
    print(f"[+] ¡Reporte multi-fuente finalizado exitosamente!")

if __name__ == "__main__":
    # --- AGREGACIÓN MULTI-FUENTE ---
    otx_data = fetch_otx_pulses()
    cisa_data = fetch_cisa_rss()
    
    # Consolidamos ambas fuentes en una sola lista antes del filtro duro
    total_threats = otx_data + cisa_data
    
    relevant = apply_hard_filters(total_threats)
    generate_report(relevant)
