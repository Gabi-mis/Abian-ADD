#!/bin/bash

scriptadd(){
    op=1
    while [ $op -ne 0 ]; do
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
        echo "Opción 0: Salir"
        read -p "Elegir la opción deseada: " op
        echo ""
        case $op in
            0) ;;
            1)
               # --- Bisiesto ---
                read -p "dime un año: " year
                if (( (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) )); then
                    echo "El año $year es bisiesto ✅"
                else
                    echo "El año $year NO es bisiesto ❌"
                fi
                ;;
            2)
                read -p "Introduce la IP (ej. 192.168.1.50): " IP
                read -p "Introduce la máscara (ej. 24): " MASK
                read -p "Introduce la puerta de enlace (Gateway, ej. 192.168.1.1): " GW
                read -p "Introduce el DNS (ej. 8.8.8.8): " DNS
                IFACE="enp0s3"
                sudo tee /etc/netplan/50-cloud-init.yaml > /dev/null <<EOF
network:
  ethernets:
    $IFACE:
      dhcp4: no
      addresses:
        - $IP/$MASK
      routes:
      - to: default
        via: $GW
      nameservers:
        addresses: [$DNS]
  version: 2
EOF
                sudo netplan apply
                echo -e "\n=== Configuración aplicada ==="
                ip addr show dev $IFACE
                ip route | grep default
                cat /etc/netplan/50-cloud-init.yaml
                ;;
            3)
                num=$((RANDOM % 100 + 1))
                echo "Adivina en 5 intentos un número aleatorio del 1 al 100"
                acierto=0
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
                ;;
            4)
                read -p "📂 Nombre exacto del fichero: " fichero    
                case "$(uname -s)" in                              
                    Linux) base_dir="/" ;;                            
                    MINGW*|MSYS*|CYGWIN*) base_dir="/c" ;;                           
                    *) echo "⚠️ Sistema operativo no compatible." ; exit 1 ;;                                  
                esac                                               
                echo "🔍 Buscando '$fichero' en todo el sistema..." 
                ruta=$(find "$base_dir" -type f -iname "$fichero" 2>/dev/null | head -n 1) 
                if [[ -n "$ruta" ]]; then                          
                    echo "✅ Fichero encontrado en: $ruta"          
                    vocales=$(grep -oi "[aeiou]" "$ruta" | wc -l)  
                    echo "🔡 El archivo contiene $vocales vocales." 
                else                                               
                    echo "❌ No se encontró el fichero '$fichero'"  
                fi                                                 
                ;;
            5)
                read -p "📂 Ingresa la ruta del directorio: " dir                               
                case "$(uname -s)" in                                                          
                    Linux) path="$dir" ;;                                                          
                    MINGW*|MSYS*|CYGWIN*) path=$(cygpath -u "$dir") ;;                                            
                    *) echo "⚠️ Sistema operativo no compatible." ; exit 1 ;;                                                               
                esac                                                                            
                if [ -d "$path" ]; then                                                         
                    total=$(find "$path" -maxdepth 1 -type f | wc -l)                           
                    echo "📊 En el directorio '$path' hay $total ficheros directos."           
                else                                                                            
                    echo "❌ El directorio '$path' no existe."                                   
                fi                                                                              
                ;;
            6)
                read -p "🔐 Ingresa la ruta absoluta del objeto: " objeto
                if uname | grep -qiE 'mingw|cygwin'; then
                    objeto=$(echo "$objeto" | sed -E 's|^([A-Za-z]):\\|/\L\1/|; s|\\|/|g')
                fi
                [ -e "$objeto" ] && echo "📁 Permisos octales: $(stat -c "%a" "$objeto")" && echo "🔎 Permisos simbólicos: $(stat -c "%A" "$objeto")" || echo "❌ El objeto '$objeto' no existe."
                ;;
            7)
                read -p "Ingrese un número entre 1 y 200: " numero
                if (( numero >= 1 && numero <= 200 )); then
                    valores=(100 90 50 40 10 9 5 4 1)
                    simbolos=("C" "XC" "L" "XL" "X" "IX" "V" "IV" "I")
                    romano=""
                    n=$numero
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
                ;;
            8)
                DIR="/mnt/usuarios"
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
                ;;
            9)
                read -p "Ingrese el nombre del fichero (por defecto 'fichero_vacio'): " nombre
                nombre=${nombre:-fichero_vacio}
                read -p "Ingrese el tamaño en KB (por defecto 1024): " tam
                tam=${tam:-1024}
                truncate -s "${tam}K" $nombre
                echo "✅ Fichero '$nombre' creado con tamaño $tam KB"
                ;;
            10)
                read -p "Nombre del fichero (defecto 'fichero_vacio'): " nombre
                nombre=${nombre:-fichero_vacio}
                read -p "Tamaño en KB (defecto 1024): " tam
                tam=${tam:-1024}
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
                ;;
            11)
                read -p "Ingrese la palabra: " palabra
                [ -z "$palabra" ] && { echo "❌ No se ingresó ninguna palabra."; break; }
                resultado=$(echo "$palabra" | tr 'aeiouAEIOU' '1234512345')
                echo "Palabra reescrita: $resultado"
                ;;
            12)
                usuarios=( $(ls /home) )
                [ ${#usuarios[@]} -eq 0 ] && { echo "❌ No hay usuarios en /home."; break; }
                echo "📋 Usuarios encontrados:"
                for i in "${!usuarios[@]}"; do echo "$((i+1))) ${usuarios[i]}"; done
                read -p "Seleccione el número del usuario a respaldar: " opcion
                [[ ! "$opcion" =~ ^[0-9]+$ || "$opcion" -lt 1 || "$opcion" -gt ${#usuarios[@]} ]] && { echo "❌ Opción inválida."; break; }
                usuario="${usuarios[$((opcion-1))]}"
                destino="/home/copiaseguridad/${usuario}_$(date +%Y%m%d_%H%M%S)"
                mkdir -p "$destino"
                cp -a "/home/$usuario/." "$destino"
                echo "✅ Copia de seguridad de '$usuario' realizada en: $destino"
                ;;
            13)
                dir="."
                [ ! -d "$dir" ] && { echo "❌ El directorio '$dir' no existe."; break; }
                for fichero in "$dir"/*; do
                    nombre=$(basename "$fichero")
                    [[ "$nombre" == *" "* ]] && mv -v "$fichero" "$dir/${nombre// /_}"
                done
                ;;
            14)
                read -p "Ingrese un carácter: " c
                read -p "Ingrese número de caracteres por línea (1-60): " n
                read -p "Ingrese número de líneas (1-10): " l
                [[ ! $n =~ ^[0-9]+$ || $n -lt 1 || $n -gt 60 ]] && { echo "❌ Número de caracteres debe ser 1-60"; break; }
                [[ ! $l =~ ^[0-9]+$ || $l -lt 1 || $l -gt 10 ]] && { echo "❌ Número de líneas debe ser 1-10"; break; }
                for ((i=0;i<l;i++)); do
                    printf "%${n}s\n" "" | tr ' ' "$c"
                done
                ;;
            *)
                echo "Opción incorrecta"
                ;;
        esac
    done
}
scriptadd
