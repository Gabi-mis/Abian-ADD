#!/bin/bash

read -p "📂 Ingresa el nombre exacto del fichero: " fichero

# Buscar en la carpeta de usuario de Windows
ruta=$(find /c/Users -type f -name "$fichero" 2>/dev/null | head -n 1)

if [ -z "$ruta" ]; then
    echo "❌ No se encontró el fichero '$fichero' en C:/Users"
    exit 1
fi

echo "✅ Fichero encontrado en: $ruta"

# Contar vocales (minúsculas y mayúsculas)
vocales=$(grep -o -i "[aeiou]" "$ruta" | wc -l)
echo "🔡 El archivo contiene $vocales vocales."

