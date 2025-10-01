# ==============================
# Funciones
# ==============================

function Pizza {
    param($tipo, $ingrediente)
    if ($tipo -eq "s") {
        if ($ingrediente -match ",| ") { Write-Host "❌ Solo puedes elegir UN ingrediente." }
        else { Write-Host "`n👉 Tu pizza VEGETARIANA lleva: Mozzarella, Tomate y $ingrediente" }
    }
    elseif ($tipo -eq "n") {
        if ($ingrediente -match ",| ") { Write-Host "❌ Solo puedes elegir UN ingrediente." }
        else { Write-Host "`n👉 Tu pizza NO VEGETARIANA lleva: Mozzarella, Tomate y $ingrediente" }
    }
    else { Write-Host "❌ Opción inválida." }
}

function Dias {
    param($anio)
    if ( ($anio % 400 -eq 0) -or ( ($anio % 4 -eq 0) -and ($anio % 100 -ne 0) ) ) {
        $diasPares = 0; $diasImpares = 0
        for ($i = 1; $i -le 366; $i++) { if ($i % 2 -eq 0) { $diasPares++ } else { $diasImpares++ } }
        Write-Host "`n📅 El año $anio es bisiesto."
        Write-Host "✅ Días pares: $diasPares"
        Write-Host "✅ Días impares: $diasImpares"
    }
    else { Write-Host "❌ El año $anio no es bisiesto, este cálculo solo aplica a años bisiestos." }
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
        "crear" { New-LocalGroup -Name $grupo; Write-Host "Grupo $grupo creado." }
        "eliminar" { Remove-LocalGroup -Name $grupo; Write-Host "Grupo $grupo eliminado." }
        "agregar_miembro" { Add-LocalGroupMember -Group $grupo -Member $usuario; Write-Host "Usuario $usuario agregado al grupo $grupo." }
        "quitar_miembro" { Remove-LocalGroupMember -Group $grupo -Member $usuario; Write-Host "Usuario $usuario eliminado del grupo $grupo." }
        Default { Write-Host "Acción inválida" }
    }
}

function Diskp {
    param($numDisco)
    $disco = Get-Disk -Number $numDisco -ErrorAction SilentlyContinue
    if (-not $disco) { Write-Host "❌ Disco $numDisco no encontrado."; return }
    $tamanioGB = [math]::Round($disco.Size / 1GB, 2)
    Write-Host "ℹ️ Disco $numDisco tamaño: $tamanioGB GB"
    $scriptDiskpart = "$env:TEMP\diskpart_script.txt"
    $contenido = @()
    $contenido += "select disk $numDisco"
    $contenido += "clean"
    $contenido += "convert gpt"
    $particiones = [math]::Floor($tamanioGB)
    for ($i = 1; $i -le $particiones; $i++) { $contenido += "create partition primary size=1024" }
    $contenido | Set-Content $scriptDiskpart -Encoding ASCII
    Write-Host "🚀 Ejecutando Diskpart..."
    Start-Process diskpart -ArgumentList "/s `"$scriptDiskpart`"" -Wait
    Write-Host "✅ Disco $numDisco formateado y particionado en $particiones particiones de 1GB."
    Remove-Item $scriptDiskpart -Force
}

function Comprobar-Contraseña {
    param($password)
    if ($password.Length -ge 8) { Write-Host "✔️ Longitud correcta (8 o más caracteres)" }
    else { Write-Host "❌ Debe tener al menos 8 caracteres" }
    if ($password -match "[a-z]") { Write-Host "✔️ Contiene minúsculas" }
    else { Write-Host "❌ Falta al menos una minúscula" }
    if ($password -match "[A-Z]") { Write-Host "✔️ Contiene mayúsculas" }
    else { Write-Host "❌ Falta al menos una mayúscula" }
    if ($password -match "[0-9]") { Write-Host "✔️ Contiene números" }
    else { Write-Host "❌ Falta al menos un número" }
    if ($password -match "[^a-zA-Z0-9]") { Write-Host "✔️ Contiene caracteres especiales" }
    else { Write-Host "❌ Falta al menos un carácter especial" }
    if (
        $password.Length -ge 8 -and
        $password -match "[a-z]" -and
        $password -match "[A-Z]" -and
        $password -match "[0-9]" -and
        $password -match "[^a-zA-Z0-9]"
    ) {
        Write-Host "`n✅ La contraseña es válida."
    }
    else {
        Write-Host "`n⚠️ La contraseña no es válida."
    }
}

function Fibonacci {
    param($n)
    if ($n -lt 1) {
        Write-Host "❌ Debes introducir un número mayor o igual a 1."
        return
    }
    $a = 0
    $b = 1
    Write-Host "`nSerie de Fibonacci ($n primeros números):"
    for ($i = 1; $i -le $n; $i++) {
        Write-Host $a -NoNewline
        if ($i -lt $n) { Write-Host ", " -NoNewline }
        $siguiente = $a + $b
        $a = $b
        $b = $siguiente
    }
    Write-Host ""
}

function FibonacciRecursiva {
    param([int]$n)

    function Fib {
        param([int]$x)
        if ($x -eq 0) { return 0 }
        elseif ($x -eq 1) { return 1 }
        else { return (Fib ($x - 1) + Fib ($x - 2)) }
    }

    if ($n -lt 1) {
        Write-Host "❌ Debes introducir un número mayor o igual a 1."
        return
    }

    Write-Host "`n🔁 Serie de Fibonacci recursiva ($n primeros números):"
    for ($i = 0; $i -lt $n; $i++) {
        Write-Host (Fib $i) -NoNewline
        if ($i -lt $n - 1) { Write-Host ", " -NoNewline }
    }
    Write-Host ""
}

function Monitoreo {
    param([int]$duracion, [int]$intervalo)

    $medidas = @()
    $iteraciones = [math]::Floor($duracion / $intervalo)

    Write-Host "`n🖥️ Monitoreando uso de CPU durante $duracion segundos (cada $intervalo segundos)...`n"

    for ($i = 1; $i -le $iteraciones; $i++) {
        $cpu = (Get-WmiObject -Query "SELECT LoadPercentage FROM Win32_Processor").LoadPercentage
        $cpuRedondeado = [math]::Round($cpu, 2)
        $medidas += $cpuRedondeado
        Write-Host "🔹 Medida ${i}: ${cpuRedondeado} %"
        Start-Sleep -Seconds $intervalo
    }

    $promedio = ($medidas | Measure-Object -Average).Average
    $promedio = [math]::Round($promedio, 2)

    Write-Host "`n📊 Promedio de uso de CPU: $promedio %"
}

function AlertaEspacio {
    param([string]$logPath)

    $unidades = Get-PSDrive -PSProvider 'FileSystem'
    $fecha = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    foreach ($unidad in $unidades) {
        $total = $unidad.Used + $unidad.Free
        if ($total -eq 0) { continue }  # Evita división por cero

        $porcentajeLibre = ($unidad.Free / $total) * 100
        $porcentajeLibre = [math]::Round($porcentajeLibre, 2)

        if ($porcentajeLibre -lt 10) {
            $mensaje = "⚠️ [$fecha] Unidad ${unidad.Name}: solo ${porcentajeLibre}% libre. ¡Espacio crítico!"
            Write-Host $mensaje
            Add-Content -Path $logPath -Value $mensaje
        } else {
            Write-Host "✅ Unidad ${unidad.Name}: ${porcentajeLibre}% libre. Todo bien."
        }
    }
}

function CopiasMasivas {
    param()

    $rutaDestinoBase = "C:\CopiasSeguridad"

    if (-not (Test-Path -Path $rutaDestinoBase)) {
        New-Item -Path $rutaDestinoBase -ItemType Directory | Out-Null
        Write-Host "📁 Carpeta '$rutaDestinoBase' creada."
    }

    $usuarios = Get-ChildItem -Path "C:\Users" -Directory

    foreach ($usuario in $usuarios) {
        $nombreUsuario = $usuario.Name
        $rutaOrigen = "C:\Users\$nombreUsuario"
        $rutaDestino = "$rutaDestinoBase\$nombreUsuario.zip"

        try {
            Compress-Archive -Path $rutaOrigen -DestinationPath $rutaDestino -Force
            Write-Host "✅ Copia creada para el usuario: $nombreUsuario"
        }
        catch {
            Write-Host "❌ Error al copiar el perfil de $nombreUsuario $_"
        }
    }
}

function automatizarps {
    param()

    $directorio = "C:\usuarios"
    $archivos = Get-ChildItem -Path $directorio -File -Filter *.txt

    if ($archivos.Count -eq 0) {
        Write-Host "📂 No hay archivos en $directorio"
        return
    }

    foreach ($archivo in $archivos) {
        $usuario = $archivo.BaseName
        $carpetas = Get-Content $archivo.FullName

        New-LocalUser -Name $usuario -Password (ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force)
        Write-Host "👤 Usuario '$usuario' creado."

        foreach ($nombreCarpeta in $carpetas) {
            New-Item -Path "C:\Users\$usuario\$nombreCarpeta" -ItemType Directory -Force | Out-Null
        }

        Remove-Item $archivo.FullName -Force
        Write-Host "🗑️ Archivo '$($archivo.Name)' eliminado."
    }
}

function barrido {
    param(
        [string]$baseIP,
        [int]$inicio = 1,
        [int]$fin = 254
    )

    if (-not ($baseIP -match '^(\d{1,3}\.){3}$')) {
        Write-Host "❌ IP base inválida. Debe terminar en punto, ej. 192.168.1."
        return
    }

    $ipActivas = @()
    Write-Host "`n🌐 Barrido de red $baseIP$inicio a $baseIP$fin..."

    for ($i = $inicio; $i -le $fin; $i++) {
        $ip = "$baseIP$i"
        if (Test-Connection -ComputerName $ip -Count 1 -Quiet) {
            Write-Host "✅ $ip"
            $ipActivas += $ip
        } else {
            Write-Host "❌ $ip"
        }
    }

    $archivo = "C:\SCRPW\ips_activas.txt"
    $ipActivas | Set-Content $archivo
    Write-Host "`n📄 IPs activas guardadas en $archivo"
}

function evento {
    param([int]$cantidad = 200)

    $eventos = Get-WinEvent -LogName System, Application -MaxEvents $cantidad |
        Where-Object { $_.LevelDisplayName -in @("Error", "Critical") } |
        Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message

    $ruta = "$env:USERPROFILE\eventos.csv"
    $eventos | Export-Csv -Path $ruta -NoTypeInformation -Encoding UTF8

    Write-Host "`n📄 Eventos exportados a: $ruta"
}

function Agenda {
    param()

    $agenda = @{}
    $salir = $false

    while (-not $salir) {
        Write-Host "`n📒 Menú Agenda:"
        Write-Host "1. Añadir/modificar"
        Write-Host "2. Buscar"
        Write-Host "3. Borrar"
        Write-Host "4. Listar"
        Write-Host "5. Salir"

        $op = Read-Host "Elige una opción"

        switch ($op) {
            "1" {
                $nombre = Read-Host "Nombre"
                if ($agenda.ContainsKey($nombre)) {
                    Write-Host "📞 Teléfono actual: $($agenda[$nombre])"
                    $modificar = Read-Host "¿Deseas modificarlo? (s/n)"
                    if ($modificar -eq "s") {
                        $telefono = Read-Host "Nuevo teléfono"
                        $agenda[$nombre] = $telefono
                        Write-Host "✅ Teléfono actualizado."
                    }
                } else {
                    $telefono = Read-Host "Teléfono"
                    $agenda[$nombre] = $telefono
                    Write-Host "✅ Contacto añadido."
                }
            }
            "2" {
                $cadena = Read-Host "Buscar nombres que comiencen por"
                $resultados = $agenda.Keys | Where-Object { $_ -like "$cadena*" }
                foreach ($nombre in $resultados) {
                    Write-Host "$nombre : $($agenda[$nombre])"
                }
            }
            "3" {
                $nombre = Read-Host "Nombre a borrar"
                if ($agenda.ContainsKey($nombre)) {
                    $confirmar = Read-Host "¿Seguro que quieres borrarlo? (s/n)"
                    if ($confirmar -eq "s") {
                        $agenda.Remove($nombre)
                        Write-Host "🗑️ Contacto eliminado."
                    }
                } else {
                    Write-Host "❌ No se encontró el contacto."
                }
            }
            "4" {
                Write-Host "`n📋 Agenda completa:"
                foreach ($nombre in $agenda.Keys) {
                    Write-Host "$nombre : $($agenda[$nombre])"
                }
            }
            "5" {
                Write-Host "👋 Saliendo de la agenda..."
                $salir = $true
            }
            Default {
                Write-Host "❌ Opción inválida."
            }
        }
    }
}



# ==============================
# Menú principal
# ==============================

function Mostrar-Menu {
    Write-Host "`nOpción Pizza"
    Write-Host "Opción Dias"
    Write-Host "Opción Usuarios"
    Write-Host "Opción Grupos"
    Write-Host "Opción Diskp"
    Write-Host "Opción Contraseña"
    Write-Host "Opción Fibonacci"
    Write-Host "Opción Fibonacci Recursiva"
    Write-Host "Opción Monitoreo"
    Write-Host "Opción Espacio"
    Write-Host "Opción copias"
    Write-Host "Opción automatizar"
    Write-Host "Opción barrido"
    Write-Host "Opción evento"
    Write-Host "Opción agenda"
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
        "Contraseña" {
            $password = Read-Host "Introduce una contraseña a validar"
            Comprobar-Contraseña -password $password
        }
        "Fibonacci" {
            $n = Read-Host "Introduce cuántos números de Fibonacci quieres imprimir"
            Fibonacci -n $n
        }
        "Recursiva" {
            $n = Read-Host "Introduce cuántos números de Fibonacci quieres imprimir (recursiva)"
        if ($n -match '^\d+$') {
            $n = [int]$n
        FibonacciRecursiva -n $n
        } else {
        Write-Host "❌ Entrada inválida. Debes introducir un número entero positivo."
            }
        }
        "Monitoreo" {
            $duracion = 30
            $intervalo = 5
            Monitoreo -duracion $duracion -intervalo $intervalo
        }

        "espacio" {
            $logPath = "$env:USERPROFILE\alertaEspacio.log"
            AlertaEspacio -logPath $logPath
        }
        "copias" {
            CopiasMasivas
        }
        "automatizar" {
            automatizarps
        }
        "barrido" {
            $baseIP = Read-Host "IP base (ej. 192.168.1.)"
            $inicio = Read-Host "IP inicial (ej. 1)"
            $fin = Read-Host "IP final (ej. 254)"
            barrido -baseIP $baseIP -inicio $inicio -fin $fin
        }
        "evento" {
            $cantidad = Read-Host "¿Cuántos eventos quieres extraer? (ej. 200)"
            evento -cantidad $cantidad
        }
        "Agenda" {
            Agenda
        }
        "Salir" { Write-Host "Saliendo..." }
        Default { Write-Host "Opción incorrecta" }
    }
}
