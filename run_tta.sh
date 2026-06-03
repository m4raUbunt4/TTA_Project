#!/usr/bin/env bash

# TTA Wrapper - Fase 0 (Smoke Test)
set -euo pipefail
#!/usr/bin/env bash
# TTA Wrapper - Fase 1
set -euo pipefail

# 1. Cargar variables de entorno
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
else
    echo "[-] Error: Archivo .env no encontrado."
    exit 1
fi

echo "[+] Entorno cargado correctamente en Debian 13."

# 2. Smoke Test de la IA
echo "[*] Verificando estado del motor de IA (Gemini)..."
RESPONSE=$(curl -s -X POST "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GEMINI_API_KEY}" \
     -H 'Content-Type: application/json' \
     -d '{"contents": [{"parts":[{"text": "Hola, responde únicamente con la palabra PING"}]}]}')

if echo "$RESPONSE" | grep -q "PING"; then
    echo "[+] Conexión con Gemini API: OK"
else
    echo "[-] Error crítico: La IA no responde correctamente."
    exit 1
fi

echo "--------------------------------------------------"

# 3. Ejecutar Extracción y Filtrado de la Fase 1
python3 src/extract_otx.py

