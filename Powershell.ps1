# ==============================
# Funciones
# ==============================

function Pizza {
    param($tipo, $ingrediente)

    if ($tipo -eq "s") {
        if ($ingrediente -match ",| ") {
            Write-Host "❌ Solo puedes elegir UN ingrediente."
        }
        else {
            Write-Host "`n👉 Tu pizza VEGETARIANA lleva: Mozzarella, Tomate y $ingrediente"
        }
    }
    elseif ($tipo -eq "n") {
        if ($ingrediente -match ",| ") {
            Write-Host "❌ Solo puedes elegir UN ingrediente."
        }
        else {
            Write-Host "`n👉 Tu pizza NO VEGETARIANA lleva: Mozzarella, Tomate y $ingrediente"
        }
    }
    else {
        Write-Host "❌ Opción inválida."
    }
}

function Dias {
    param($anio)

    if ( ($anio % 400 -eq 0) -or ( ($anio % 4 -eq 0) -and ($anio % 100 -ne 0) ) ) {
        $diasPares = 0
        $diasImpares = 0

        for ($i = 1; $i -le 366; $i++) {
            if ($i % 2 -eq 0) { $diasPares++ }
            else { $diasImpares++ }
        }

        Write-Host "`n📅 El año $anio es bisiesto."
        Write-Host "✅ Días pares: $diasPares"
        Write-Host "✅ Días impares: $diasImpares"
    }
    else {
        Write-Host "❌ El año $anio no es bisiesto, este cálculo solo aplica a años bisiestos."
    }
}

function Usuarios {
    param($accion, $usuario, $password, $nuevoNombre)

    switch ($accion) {
        "listar" { Get-LocalUser | Select-Object Name | Out-Host }
        "crear" {
            New-LocalUser -Name $usuario -Password (ConvertTo-SecureString $password -AsPlainText -Force)
            Write-Host "Usuario $usuario creado."
        }
        "eliminar" {
            Remove-LocalUser -Name $usuario
            Write-Host "Usuario $usuario eliminado."
        }
        "modificar" {
            Rename-LocalUser -Name $usuario -NewName $nuevoNombre
            Write-Host "Usuario $usuario renombrado a $nuevoNombre."
        }
        Default { Write-Host "Acción inválida" }
    }
}

function Grupos {
    param($accion, $grupo, $usuario)

    switch ($accion) {
        "listar" {
            Get-LocalGroup | ForEach-Object {
                $nombre = $_.Name
                $miembros = Get-LocalGroupMember -Group $nombre | Select-Object -ExpandProperty Name
                Write-Host "`nGrupo: $nombre"
                Write-Host "Miembros: $($miembros -join ', ')"
            }
        }
        "crear" {
            New-LocalGroup -Name $grupo
            Write-Host "Grupo $grupo creado."
        }
        "eliminar" {
            Remove-LocalGroup -Name $grupo
            Write-Host "Grupo $grupo eliminado."
        }
        "agregar_miembro" {
            Add-LocalGroupMember -Group $grupo -Member $usuario
            Write-Host "Usuario $usuario agregado al grupo $grupo."
        }
        "quitar_miembro" {
            Remove-LocalGroupMember -Group $grupo -Member $usuario
            Write-Host "Usuario $usuario eliminado del grupo $grupo."
        }
        Default { Write-Host "Acción inválida" }
    }
}

function Diskp {
    param($numDisco)

    # Obtenemos información del disco
    $disco = Get-Disk -Number $numDisco -ErrorAction SilentlyContinue
    if (-not $disco) {
        Write-Host "❌ Disco $numDisco no encontrado."
        return
    }

    $tamanioGB = [math]::Round($disco.Size / 1GB, 2)
    Write-Host "ℹ️ Disco $numDisco tamaño: $tamanioGB GB"

    # Creamos script temporal para Diskpart
    $scriptDiskpart = "$env:TEMP\diskpart_script.txt"
    $contenido = @()
    $contenido += "select disk $numDisco"
    $contenido += "clean"
    $contenido += "convert gpt"

    # Calculamos cuántas particiones de 1GB caben
    $particiones = [math]::Floor($tamanioGB)
    for ($i = 1; $i -le $particiones; $i++) {
        $contenido += "create partition primary size=1024"
    }

    $contenido | Set-Content $scriptDiskpart -Encoding ASCII

    # Ejecutamos diskpart con el script
    Write-Host "🚀 Ejecutando Diskpart..."
    Start-Process diskpart -ArgumentList "/s `"$scriptDiskpart`"" -Wait

    Write-Host "✅ Disco $numDisco formateado y particionado en $particiones particiones de 1GB."
    Remove-Item $scriptDiskpart -Force
}

function Adivina {}
function Buscar {}
function Contar {}
function PermisosOctal {}
function Romano {}
function Automatizar {}
function CrearFichero {}
function CrearFichero_NoSobrescribir {}
function ReescribirPalabra {}
function ContUsu {}
function Quita_Blancos {}
function Lineas {}
function Analizar_Directorio {}

# ==============================
# Menú principal
# ==============================

function Mostrar-Menu {
    Write-Host "`nOpción Pizza"
    Write-Host "Opción Dias"
    Write-Host "Opción Usuarios"
    Write-Host "Opción Grupos"
    Write-Host "Opción Diskp"
    Write-Host "Opción Adivina"
    Write-Host "Opción Buscar"
    Write-Host "Opción Contar"
    Write-Host "Opción PermisosOctal"
    Write-Host "Opción Romano"
    Write-Host "Opción Automatizar"
    Write-Host "Opción CrearFichero"
    Write-Host "Opción CrearFichero_NoSobrescribir"
    Write-Host "Opción ReescribirPalabra"
    Write-Host "Opción ContUsu"
    Write-Host "Opción Quita_Blancos"
    Write-Host "Opción Lineas"
    Write-Host "Opción Analizar_Directorio"
    Write-Host "Opción Salir"
}

# ==============================
# Bucle y switch
# ==============================

$op = ""
while ($op -ne "Salir") {
    Mostrar-Menu
    $op = Read-Host "Elige una opción"
    Write-Host ""

    switch ($op) {
        "Pizza" {
            $tipo = Read-Host "¿Quieres una pizza vegetariana? (s/n)"
            if ($tipo -eq "s") { $ingrediente = Read-Host "Elige un ingrediente (Pimiento/Tofu)" }
            elseif ($tipo -eq "n") { $ingrediente = Read-Host "Elige un ingrediente (Peperoni/Jamón/Salmón)" }
            else { $ingrediente = "" }
            Pizza -tipo $tipo -ingrediente $ingrediente
        }
        "Dias" {
            $anio = Read-Host "Introduce un año (ejemplo: 2024)"
            Dias -anio $anio
        }
        "Usuarios" {
            Write-Host "`nAcciones disponibles: listar, crear, eliminar, modificar"
            $accion = Read-Host "Qué acción quieres realizar"
            if ($accion -eq "crear") {
                $usuario = Read-Host "Nombre del nuevo usuario"
                $password = Read-Host "Contraseña del nuevo usuario"
                Usuarios -accion $accion -usuario $usuario -password $password
            }
            elseif ($accion -eq "eliminar") {
                $usuario = Read-Host "Nombre del usuario a eliminar"
                Usuarios -accion $accion -usuario $usuario
            }
            elseif ($accion -eq "modificar") {
                $usuario = Read-Host "Nombre del usuario a modificar"
                $nuevoNombre = Read-Host "Nuevo nombre del usuario"
                Usuarios -accion $accion -usuario $usuario -nuevoNombre $nuevoNombre
            }
            elseif ($accion -eq "listar") { Usuarios -accion $accion }
            else { Write-Host "Acción inválida" }
        }
        "Grupos" {
            Write-Host "`nAcciones disponibles: listar, crear, eliminar, agregar_miembro, quitar_miembro"
            $accion = Read-Host "Qué acción quieres realizar"
            if ($accion -eq "crear") {
                $grupo = Read-Host "Nombre del grupo a crear"
                Grupos -accion $accion -grupo $grupo
            }
            elseif ($accion -eq "eliminar") {
                $grupo = Read-Host "Nombre del grupo a eliminar"
                Grupos -accion $accion -grupo $grupo
            }
            elseif ($accion -eq "agregar_miembro") {
                $grupo = Read-Host "Grupo al que agregar el usuario"
                $usuario = Read-Host "Usuario a agregar"
                Grupos -accion $accion -grupo $grupo -usuario $usuario
            }
            elseif ($accion -eq "quitar_miembro") {
                $grupo = Read-Host "Grupo del que quitar el usuario"
                $usuario = Read-Host "Usuario a quitar"
                Grupos -accion $accion -grupo $grupo -usuario $usuario
            }
            elseif ($accion -eq "listar") { Grupos -accion $accion }
            else { Write-Host "Acción inválida" }
        }
        "Diskp" {
            $numDisco = Read-Host "Introduce el número del disco a utilizar"
            Diskp -numDisco $numDisco
        }
        "Adivina" { Adivina }
        "Buscar" { Buscar }
        "Contar" { Contar }
        "PermisosOctal" { PermisosOctal }
        "Romano" { Romano }
        "Automatizar" { Automatizar }
        "CrearFichero" { CrearFichero }
        "CrearFichero_NoSobrescribir" { CrearFichero_NoSobrescribir }
        "ReescribirPalabra" { ReescribirPalabra }
        "ContUsu" { ContUsu }
        "Quita_Blancos" { Quita_Blancos }
        "Lineas" { Lineas }
        "Analizar_Directorio" { Analizar_Directorio }
        "Salir" { Write-Host "Saliendo..." }
        Default { Write-Host "Opción incorrecta" }
    }
}
