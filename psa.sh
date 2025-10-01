#!/bin/bash

# ==============================
# Funciones (sin lecturas dentro)
# ==============================

bisiesto() {
    local year=$1
    if (( (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) )); then
        echo "El año $year es bisiesto ✅"
    else
        echo "El año $year NO es bisiesto ❌"
    fi
}

configurarred() {
    IFACE="enp0s3"
    sudo tee /etc/netplan/50-cloud-init.yaml > /dev/null <<EOF
network:
  ethernets:
    $IFACE:
      dhcp4: no
      addresses:
        - $1/$2
      routes:
      - to: default
        via: $3
      nameservers:
        addresses: [$4]
  version: 2
EOF
    sudo netplan apply
}

adivina() {
    local num=$((RANDOM % 101))
    echo "Adivina en 5 intentos un número aleatorio del 1 al 100"
    local acierto=0
    for i in $(seq 1 5); do
      read -p "Intento $i: " x
      if [ "$x" -eq "$num" ]; then
          echo "🎉 ¡Enhorabuena! Adivinaste en $i intentos!"
          acierto=1
          break
      elif [ "$x" -lt "$num" ]; then
          echo "El número es MAYOR"
      else
          echo "El número es MENOR"
      fi
    done
    [ $acierto -eq 0 ] && echo "❌ Sin intentos. El número era: $num"
}

buscar() {
    local fichero=$1
    case "$(uname -s)" in
        Linux) base_dir="/" ;;
        MINGW*|MSYS*|CYGWIN*) base_dir="/c" ;;
        *) echo "⚠️ Sistema operativo no compatible." ; exit 1 ;;
    esac
    echo "🔍 Buscando '$fichero' en todo el sistema..."
    local ruta=$(find "$base_dir" -type f -iname "$fichero" 2>/dev/null | head -n 1)
    if [[ -n "$ruta" ]]; then
        echo "✅ Fichero encontrado en: $ruta"
        local vocales=$(grep -oi "[aeiou]" "$ruta" | wc -l)
        echo "🔡 El archivo contiene $vocales vocales."
    else
        echo "❌ No se encontró el fichero '$fichero'"
    fi
}

contar() {
    local dir=$1
    case "$(uname -s)" in
        Linux) path="$dir" ;;
        MINGW*|MSYS*|CYGWIN*) path=$(cygpath -u "$dir") ;;
        *) echo "⚠️ Sistema operativo no compatible." ; exit 1 ;;
    esac
    if [ -d "$path" ]; then
        local total=$(find "$path" -maxdepth 1 -type f | wc -l)
        echo "📊 En el directorio '$path' hay $total ficheros directos."
    else
        echo "❌ El directorio '$path' no existe."
    fi
}

permisosoctal() {
    local objeto=$1
    if uname | grep -qiE 'mingw|cygwin'; then
        objeto=$(echo "$objeto" | sed -E 's|^([A-Za-z]):\\|/\L\1/|; s|\\|/|g')
    fi
    [ -e "$objeto" ] && echo "📁 Permisos octales: $(stat -c "%a" "$objeto")" && echo "🔎 Permisos simbólicos: $(stat -c "%A" "$objeto")" || echo "❌ El objeto '$objeto' no existe."
}

romano() {
    local numero=$1
    if (( numero >= 1 && numero <= 200 )); then
        local valores=(100 90 50 40 10 9 5 4 1)
        local simbolos=("C" "XC" "L" "XL" "X" "IX" "V" "IV" "I")
        local romano=""
        local n=$numero
        for i in "${!valores[@]}"; do
          while (( n >= valores[i] )); do
            romano+=${simbolos[i]}
            (( n -= valores[i] ))
          done
        done
        echo "$numero en romano es: $romano"
    else
        echo "⚠️ Número fuera de rango (1-200)."
    fi
}

automatizar() {
    local DIR="/mnt/usuarios"
    if [ -z "$(ls -A $DIR 2>/dev/null)" ]; then
        echo "📂 Listado vacío en $DIR"
    else
        for fichero in "$DIR"/*; do
            usuario=$(basename "$fichero")
            echo "👤 Creando usuario: $usuario"
            useradd -m "$usuario"
            while read -r carpeta; do
                mkdir -p "/home/$usuario/$carpeta"
            done < "$fichero"
            rm -f "$fichero"
            echo "✅ Procesado archivo: $fichero"
        done
    fi
}

crearfichero() {
    local nombre=$1 tam=$2
    truncate -s "${tam}K" "$nombre"
    echo "✅ Fichero '$nombre' creado con tamaño $tam KB"
}

crearfichero_nosobrescribir() {
    local nombre=$1 tam=$2
    base="${nombre%.*}"
    ext="${nombre##*.}"
    [ "$base" = "$ext" ] && ext=""
    if [ -e "$nombre" ]; then
        for i in {1..9}; do
            candidato="$base$i${ext:+.$ext}"
            [ ! -e "$candidato" ] && nombre="$candidato" && break
        done
        [ -e "$nombre" ] && echo "❌ Ya existen '$base' con versiones 1-9" && exit 1
    fi
    truncate -s "${tam}K" "$nombre"
    echo "✅ Fichero '$nombre' creado con tamaño $tam KB"
}

reescribirpalabra() {
    local palabra=$1
    [ -z "$palabra" ] && { echo "❌ No se ingresó ninguna palabra."; return; }
    resultado=$(echo "$palabra" | tr 'aeiouAEIOU' '1234512345')
    echo "Palabra reescrita: $resultado"
}

contusu() {
    local usuario=$1
    destino="/home/copiaseguridad/${usuario}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$destino"
    cp -a "/home/$usuario/." "$destino"
    echo "✅ Copia de seguridad de '$usuario' realizada en: $destino"
}

quita_blancos() {
    local dir=$1
    [ ! -d "$dir" ] && { echo "❌ El directorio '$dir' no existe."; return; }
    for fichero in "$dir"/*; do
        nombre=$(basename "$fichero")
        [[ "$nombre" == *" "* ]] && mv -v "$fichero" "$dir/${nombre// /_}"
    done
}

lineas() {
    local c=$1 n=$2 l=$3
    for ((i=0;i<l;i++)); do
        printf "%${n}s\n" "" | tr ' ' "$c"
    done
}

analizar_directorio() {
    local DIR=$1; shift
    local EXT=$@
    echo "===================================="
    echo " Informe del directorio: $DIR"
    echo " Extensiones: $EXT"
    echo "===================================="
    for ext in $EXT; do
        echo ".$ext -> $(find "$DIR" -type f -iname "*.$ext" | wc -l) archivos"
    done
}

# ==============================
# Menú principal
# ==============================

menu() {
    echo -e "\nOpción 1: bisiesto"
    echo "Opción 2: configurarred"
    echo "Opción 3: adivina"
    echo "Opción 4: buscar"
    echo "Opción 5: contar"
    echo "Opción 6: permisosoctal"
    echo "Opción 7: romano"
    echo "Opción 8: automatizar"
    echo "Opción 9: crear fichero"
    echo "Opción 10: crear fichero (evitar sobrescribir)"
    echo "Opción 11: reescribir palabra"
    echo "Opción 12: contusu (copia seguridad usuario)"
    echo "Opción 13: quita_blancos (renombrar ficheros)"
    echo "Opción 14: lineas (dibujar líneas de caracteres)"
    echo "Opción 15: analizar directorio"
    echo "Opción 0: Salir"
}

# ==============================
# Bucle y case
# ==============================

op=1
while [ $op -ne 0 ]; do
    menu
    read -p "Elegir la opción deseada: " op
    echo ""
    case $op in
        1)
            read -p "Dime un año: " year
            bisiesto "$year"
            ;;
        2)
            read -p "IP: " ip
            read -p "Máscara: " mask
            read -p "Gateway: " gw
            read -p "DNS: " dns
            configurarred "$ip" "$mask" "$gw" "$dns"
            ;;
        3)
            adivina
            ;;
        4)
            read -p "📂 Nombre exacto del fichero: " fichero
            buscar "$fichero"
            ;;
        5)
            read -p "📂 Ingresa la ruta del directorio: " dir
            contar "$dir"
            ;;
        6)
            read -p "🔐 Ruta absoluta del objeto: " objeto
            permisosoctal "$objeto"
            ;;
        7)
            read -p "Ingrese un número entre 1 y 200: " numero
            romano "$numero"
            ;;
        8)
            automatizar
            ;;
        9)
            read -p "Nombre del fichero (defecto 'fichero_vacio'): " nombre
            nombre=${nombre:-fichero_vacio}
            read -p "Tamaño en KB (defecto 1024): " tam
            tam=${tam:-1024}
            crearfichero "$nombre" "$tam"
            ;;
        10)
            read -p "Nombre del fichero (defecto 'fichero_vacio'): " nombre
            nombre=${nombre:-fichero_vacio}
            read -p "Tamaño en KB (defecto 1024): " tam
            tam=${tam:-1024}
            crearfichero_nosobrescribir "$nombre" "$tam"
            ;;
        11)
            read -p "Ingrese la palabra: " palabra
            reescribirpalabra "$palabra"
            ;;
        12)
            usuarios=( $(ls /home) )
            for i in "${!usuarios[@]}"; do echo "$((i+1))) ${usuarios[i]}"; done
            read -p "Seleccione usuario: " opcion
            usuario="${usuarios[$((opcion-1))]}"
            contusu "$usuario"
            ;;
        13)
            read -p "Directorio donde renombrar: " dir
            quita_blancos "$dir"
            ;;
        14)
            read -p "Carácter: " c
            read -p "Nº caracteres (1-60): " n
            read -p "Nº líneas (1-10): " l
            lineas "$c" "$n" "$l"
            ;;
        15)
            read -p "Directorio: " dir
            read -p "Extensiones (separadas por espacio): " ext
            analizar_directorio "$dir" $ext
            ;;
        0)
            echo "Saliendo..."
            ;;
        *)
            echo "Opción incorrecta"
            ;;
    esac
done
