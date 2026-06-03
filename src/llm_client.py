#!/usr/bin/env python3
import os
import sys
import requests

def ask_gemini_analyst(threat_name, threat_details):
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[-] Error: GEMINI_API_KEY no encontrada en el entorno.")
        return "Error: No se pudo generar el análisis por falta de API Key."

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
    headers = {"Content-Type":"application/json"}

    # Construimos el Prompt de acuerdo a las secciones 4.2 y 4.4 de tu TTA_Spec.md
    prompt = f"""
    Actúas como un Analista de Ciberseguridad Senior y Experto en Threat Intelligence para el sector bancario en Latinoamérica.
    
    Analiza la siguiente amenaza detectada hoy en AlienVault OTX:
    - Nombre/Identificador: {threat_name}
    - Detalles técnicos iniciales: {threat_details}
    
    Genera estrictamente dos secciones en formato Markdown limpio (sin bloques de código de desborde):
    
    ### 4.2 Análisis de Contexto Empresarial (Potenciado por IA)
    - Describe brevemente qué es este tipo de amenaza (RAT de Android) y a qué tipo de organizaciones o activos afecta críticamente.
    - Explica el riesgo específico para el sector bancario (ej. troyanos bancarios móviles, suplantación de apps financieras, robo de SMS/2FA) y el impacto potencial en usuarios o empleados en Latinoamérica.
    - Menciona vectores de infección típicos (phishing, tiendas de apps de terceros, ingeniería social).
    
    ### 4.4 Guía de Acción Inmediata / Playbook (Potenciado por IA)
    - **Para Validación (Pentesting):** Indica cómo un equipo de seguridad podría validar de forma segura si sus políticas de MDM (Mobile Device Management) o controles bloquean este tipo de malware.
    - **Para Threat Hunting:** Qué buscar en los logs de red o firewalls (ej. conexiones a puertos anómalos, tráfico hacia DNS dinámicos o proxies).
    - **Para Mitigación:** Proporciona 3 contramedidas tácticas (ej. concientización sobre fraudes de phishing móvil, endurecimiento de políticas de Android corporativos, revisión de accesos condicionales).
    """

    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }

    try:
        response = requests.post(url, json=payload, timeout=30)
        response.raise_for_status()
        result = response.json()
        
        # Extraer el texto de la respuesta estructurada de Google
        return result['candidates'][0]['content']['parts'][0]['text']
    except Exception as e:
        return f"[-] Error al consultar al analista de IA: {e}"
