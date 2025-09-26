# ==============================
# Funciones (placeholders vacíos)
# ==============================

function Bisiesto {
    param($year)
    # TODO: lógica de la función
}

function ConfigurarRed {
    param($ip, $mask, $gw, $dns)
    # TODO: lógica de la función
}

function Adivina {
    # TODO: lógica de la función
}

function Buscar {
    param($fichero)
    # TODO: lógica de la función
}

function Contar {
    param($dir)
    # TODO: lógica de la función
}

function PermisosOctal {
    param($objeto)
    # TODO: lógica de la función
}

function Romano {
    param($numero)
    # TODO: lógica de la función
}

function Automatizar {
    # TODO: lógica de la función
}

function CrearFichero {
    param($nombre, $tam)
    # TODO: lógica de la función
}

function CrearFichero_NoSobrescribir {
    param($nombre, $tam)
    # TODO: lógica de la función
}

function ReescribirPalabra {
    param($palabra)
    # TODO: lógica de la función
}

function ContUsu {
    param($usuario)
    # TODO: lógica de la función
}

function Quita_Blancos {
    param($dir)
    # TODO: lógica de la función
}

function Lineas {
    param($c, $n, $l)
    # TODO: lógica de la función
}

function Analizar_Directorio {
    param($dir, $ext)
    # TODO: lógica de la función
}

# ==============================
# Menú principal
# ==============================

function Mostrar-Menu {
    Write-Host "`nOpción 1: Bisiesto"
    Write-Host "Opción 2: ConfigurarRed"
    Write-Host "Opción 3: Adivina"
    Write-Host "Opción 4: Buscar"
    Write-Host "Opción 5: Contar"
    Write-Host "Opción 6: PermisosOctal"
    Write-Host "Opción 7: Romano"
    Write-Host "Opción 8: Automatizar"
    Write-Host "Opción 9: CrearFichero"
    Write-Host "Opción 10: CrearFichero_NoSobrescribir"
    Write-Host "Opción 11: ReescribirPalabra"
    Write-Host "Opción 12: ContUsu"
    Write-Host "Opción 13: Quita_Blancos"
    Write-Host "Opción 14: Lineas"
    Write-Host "Opción 15: Analizar_Directorio"
    Write-Host "Opción 0: Salir"
}

# ==============================
# Bucle y switch (equivalente al case)
# ==============================

$op = 1
while ($op -ne 0) {
    Mostrar-Menu
    $op = Read-Host "Elegir la opción deseada"
    Write-Host ""

    switch ($op) {
        1 {
            $year = Read-Host "Dime un año"
            Bisiesto $year
        }
        2 {
            $ip   = Read-Host "IP"
            $mask = Read-Host "Máscara"
            $gw   = Read-Host "Gateway"
            $dns  = Read-Host "DNS"
            ConfigurarRed $ip $mask $gw $dns
        }
        3 {
            Adivina
        }
        4 {
            $fichero = Read-Host "📂 Nombre exacto del fichero"
            Buscar $fichero
        }
        5 {
            $dir = Read-Host "📂 Ruta del directorio"
            Contar $dir
        }
        6 {
            $objeto = Read-Host "🔐 Ruta absoluta del objeto"
            PermisosOctal $objeto
        }
        7 {
            $numero = Read-Host "Número entre 1 y 200"
            Romano $numero
        }
        8 {
            Automatizar
        }
        9 {
            $nombre = Read-Host "Nombre del fichero"
            $tam    = Read-Host "Tamaño en KB"
            CrearFichero $nombre $tam
        }
        10 {
            $nombre = Read-Host "Nombre del fichero"
            $tam    = Read-Host "Tamaño en KB"
            CrearFichero_NoSobrescribir $nombre $tam
        }
        11 {
            $palabra = Read-Host "Ingrese la palabra"
            ReescribirPalabra $palabra
        }
        12 {
            $usuario = Read-Host "Seleccione usuario"
            ContUsu $usuario
        }
        13 {
            $dir = Read-Host "Directorio donde renombrar"
            Quita_Blancos $dir
        }
        14 {
            $c = Read-Host "Carácter"
            $n = Read-Host "Nº caracteres (1-60)"
            $l = Read-Host "Nº líneas (1-10)"
            Lineas $c $n $l
        }
        15 {
            $dir = Read-Host "Directorio"
            $ext = Read-Host "Extensiones (separadas por espacio)"
            Analizar_Directorio $dir $ext
        }
        0 {
            Write-Host "Saliendo..."
        }
        Default {
            Write-Host "Opción incorrecta"
        }
    }
}
