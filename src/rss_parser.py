#!/usr/bin/env python3
import requests
import xml.etree.ElementTree as ET

def fetch_cisa_rss():
    """
    Descarga y parsea el feed RSS de avisos de seguridad de CISA.
    Normaliza el output para que sea compatible con el pipeline existente.
    """
    url = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
    print("[*] Conectando con el Feed RSS de CISA (US-CERT)...")
    
    try:
        # Los feeds RSS suelen ser muy rápidos y ligeros
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print(f"[!] CISA RSS devolvió un código de estado HTTP: {response.status_code}")
            return []
            
        # Parsear la estructura XML estándar de un RSS (channel -> item)
        root = ET.fromstring(response.content)
        rss_threats = []
        
        for item in root.findall('.//item'):
            title = item.find('title').text if item.find('title') is not None else "Aviso CISA sin título"
            link = item.find('link').text if item.find('link') is not None else ""
            description = item.find('description').text if item.find('description') is not None else "Sin descripción detallada."
            pub_date = item.find('pubDate').text if item.find('pubDate') is not None else "N/A"
            
            # --- NORMALIZACIÓN ---
            # Moldeamos el aviso de CISA para que use las mismas llaves que un pulso de AlienVault OTX
            rss_threats.append({
                "id": link.split('/')[-1] if link else "cisa_advisory",
                "name": f"[CISA Advisory] {title}",
                "description": description,
                "tags": ["cisa", "government", "us-cert", "vulnerability"],
                "created": pub_date,
                "indicators": [] # Los feeds RSS informativos no suelen traer IoCs estructurados de inmediato
            })
            
        print(f"[+] Extraídos exitosamente {len(rss_threats)} avisos recientes desde CISA.")
        return rss_threats

    except Exception as e:
        print(f"[!] Alerta: No se pudo procesar el feed RSS de CISA ({e}).")
        return []
