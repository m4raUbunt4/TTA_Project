#!/usr/bin/env python3
import os
import requests

def lookup_ioc_vt(ioc_type, ioc_value):
    """
    Consulta la API v3 de VirusTotal para obtener la reputación de un IoC.
    Mapea tipos de AlienVault OTX a endpoints de VirusTotal.
    """
    vt_key = os.getenv("VT_API_KEY")
    if not vt_key or "tu_api_key" in vt_key:
        return {"error": "VT_API_KEY no configurada."}

    # Mapear tipos de OTX a endpoints de VirusTotal v3
    # OTX usa: 'FileHash-SHA256', 'IPv4', 'Domain', 'URL', etc.
    ioc_type_lower = ioc_type.lower()
    endpoint = ""

    if "hash" in ioc_type_lower or "sha256" in ioc_type_lower or "md5" in ioc_type_lower:
        endpoint = f"files/{ioc_value}"
    elif "ipv4" in ioc_type_lower or "ip" in ioc_type_lower:
        endpoint = f"ip_addresses/{ioc_value}"
    elif "domain" in ioc_type_lower:
        endpoint = f"domains/{ioc_value}"
    else:
        # Si es un tipo no soportado directamente en este MVP, saltar
        return None

    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    headers = {"x-apikey": vt_key}

    try:
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            undetecced = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)
            suspicious = stats.get("suspicious", 0)
            total = malicious + undetecced + harmless + suspicious
            
            return {
                "status": "success",
                "malicious": malicious,
                "total": total,
                "resultado": f"{malicious}/{total} detecciones positivas"
            }
        elif response.status_code == 429:
            return {"status": "rate_limited", "resultado": "Límite de API de VT alcanzado (4 req/min)"}
        elif response.status_code == 404:
            return {"status": "not_found", "resultado": "No encontrado en la base de datos de VT"}
        else:
            return {"status": "error", "resultado": f"HTTP {response.status_code}"}
            
    except Exception as e:
        return {"status": "error", "resultado": f"Error de conexión: {e}"}
