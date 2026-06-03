#!/usr/bin/env python3
import requests

def lookup_cve(cve_id):
    """
    Busca detalles de un CVE. Intenta primero en NVD (NIST) 
    y si falla, hace un fallback automático a MITRE.
    """
    # 1. Intentar con NVD (NIST)
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        print(f"   [*] Intentando NVD para {cve_id}...")
        # Ponemos un timeout corto (5s) para que si NVD está colgado, no congele el script
        response = requests.get(nvd_url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                cve_data = vulnerabilities[0].get("cve", {})
                metrics = cve_data.get("metrics", {})
                
                # Intentar extraer el Score CVSS v3.1 o v3.0
                cvss_list = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
                score = cvss_list[0].get("cvssData", {}).get("baseScore", "N/A") if cvss_list else "N/A"
                
                descriptions = cve_data.get("descriptions", [])
                desc_text = descriptions[0].get("value", "") if descriptions else ""
                
                return {
                    "fuente": "NVD (NIST)",
                    "cvss": score,
                    "descripcion": desc_text
                }
    except Exception as e:
        print(f"   [!] NVD falló o dio timeout.")

    # 2. Fallback: Si NVD falla o no responde 200, vamos a MITRE CVE API
    mitre_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        print(f"   [!] Contingencia: Consultando MITRE para {cve_id}...")
        response = requests.get(mitre_url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            # Estructura JSON v5 de MITRE
            cna_container = data.get("containers", {}).get("cna", {})
            descriptions = cna_container.get("descriptions", [])
            desc_text = descriptions[0].get("value", "") if descriptions else "Sin descripción."
            
            # MITRE no siempre procesa el CVSS final, pero extraemos lo que tengan
            metrics = cna_container.get("metrics", [])
            score = "Revisar descripción"
            if metrics:
                # Intentar buscar un score declarado por el Vendor en MITRE
                for metric in metrics:
                    for key in ["cvssV3_1", "cvssV3_0", "cvssV4_0"]:
                        if key in metric:
                            score = metric[key].get("baseScore", score)
            
            return {
                "fuente": "MITRE CVE API",
                "cvss": score,
                "descripcion": desc_text
            }
    except Exception as e:
        print(f"   [-] Error crítico: MITRE también falló: {e}")

    # Si ambas fallan, devolvemos un esqueleto vacío para no romper el programa
    return {
        "fuente": "Ninguna (APIs caídas)",
        "cvss": "Desconocido",
        "descripcion": "No se pudo recuperar información de las bases de datos de vulnerabilidades."
    }
