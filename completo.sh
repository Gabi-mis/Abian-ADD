#!/bin/bash

# Script principal
scriptadd(){
    op=1
    while [ $op -ne 0 ]; do
        # Menú que se muestra por pantalla
        echo -e "\nOpción 1: bisiesto"
        echo "Opción 2: configurarred"
        echo "Opción 3: adivina"
        echo "Opción 4: buscar"
        echo "Opción 5: contar"
        echo "Opción 6: permisosoctal"
        echo "Opción 7: romano"
        echo "Opción 8: automatizar"
        echo "Opción 9: crear fichero"
        echo "Opción 10: crear fichero 2"
        echo "Opción 0: Salir"
        read -p "Elegir la opción deseada: " op
        echo ""
        case $op in
            0)
                ;;
            1)
                # --- Bisiesto ---
                read -p "dime un año " year
                if (( (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) )); then
                    echo "El año $year es bisiesto ✅"
                else
                    echo "El año $year NO es bisiesto ❌"
                fi
                ;;
            2)
                # --- Configurar red con Netplan ---
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
                # --- Juego de adivinanza ---
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
                if [ $acierto -eq 0 ]; then
                    echo "❌ Sin intentos. El número era: $num"
                fi
                ;;
            4)
                #!/bin/bash                                      
                                                   
                read -p "📂 Nombre exacto del fichero: " fichero    
                                                   
                # Detectar sistema operativo y ruta base           
                case "$(uname -s)" in                              
                    Linux)                                         
                    base_dir="/" ;;                            
                MINGW*|MSYS*|CYGWIN*)                          
                    base_dir="/c" ;;                           
                *)                                             
                    echo "⚠️ Sistema operativo no compatible." 
                    exit 1 ;;                                  
                esac                                               
                                                   
                echo "🔍 Buscando '$fichero' en todo el sistema..." 
                                                   
                # Buscar el archivo y contar vocales              
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
                # --- Contar ficheros en un directorio ---                                      
                read -p "📂 Ingresa la ruta del directorio: " dir                               
                                                                                
                # Detectar sistema operativo y convertir ruta si es Windows                    
                case "$(uname -s)" in                                                          
                    Linux)                                                                      
                        path="$dir" ;;                                                          
                    MINGW*|MSYS*|CYGWIN*)                                                       
                        path=$(cygpath -u "$dir") ;;                                            
                    *)                                                                          
                        echo "⚠️ Sistema operativo no compatible."                              
                        exit 1 ;;                                                               
                esac                                                                            
                                                                                
                # Verificar si el directorio existe y contar ficheros directos                
                if [ -d "$path" ]; then                                                         
                    total=$(find "$path" -maxdepth 1 -type f | wc -l)                           
                    echo "📊 En el directorio '$path' hay $total ficheros directos."           
                else                                                                            
                    echo "❌ El directorio '$path' no existe."                                   
                fi                                                                              
                ;;
            6)
               #!/bin/bash

                read -p "🔐 Ingresa la ruta absoluta del objeto: " objeto

                # Detectar si es Windows (Git Bash o similar)
                if uname | grep -qiE 'mingw|cygwin'; then
                    objeto=$(echo "$objeto" | sed -E 's|^([A-Za-z]):\\|/\L\1/|; s|\\|/|g')
                fi

                # Mostrar permisos si el objeto existe
                if [ -e "$objeto" ]; then
                    echo "📁 Permisos octales: $(stat -c "%a" "$objeto")"
                    echo "🔎 Permisos simbólicos: $(stat -c "%A" "$objeto")"
                else
                echo "❌ El objeto '$objeto' no existe."
                fi
                ;;
            7)
                # --- Conversión a números romanos ---
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
                # --- Automatizar creación de usuarios y carpetas ---
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
                # --- Crear fichero con tamaño dado ---
                read -p "Ingrese el nombre del fichero (por defecto 'fichero_vacio'): " nombre
                nombre=${nombre:-fichero_vacio}
                read -p "Ingrese el tamaño en KB (por defecto 1024): " tam
                tam=${tam:-1024}
                truncate -s "${tam}K" $nombre
                echo "✅ Fichero '$nombre' creado con tamaño $tam KB"
                ;;
            10)
                #!/bin/bash

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
                            [ -e "$nombre" ] && echo "Ya existen '$base' con versiones 1-9" && exit 1
                fi

                truncate -s "${tam}K" "$nombre"
                echo "Fichero '$nombre' creado con tamaño $tam KB"

            *)
                echo "Opción incorrecta"
                ;;
        esac
    done
}
scriptadd
