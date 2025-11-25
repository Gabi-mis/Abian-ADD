#introduccion de parametros 
param (
    [Parameter(Mandatory = $true)]
    [string]$fichero,

    [switch]$DryRun
)

# Validar que el fichero existe y es un archivo
if (!(Test-Path $fichero) -or (Get-Item $fichero).PSIsContainer) {
    Write-Host "Error: Se debe pasar un único fichero válido como parámetro." -ForegroundColor Yellow
    exit
}

# Rutas de log
$logDir = "$env:SystemRoot\System32\LogFiles"
$bajasLog = "$logDir\bajas.log"
$errorLog = "$logDir\bajaserror.log"

# Procesar cada línea del fichero
Get-Content $fichero | ForEach-Object {
    $linea = $_.Trim()
    if ($linea -eq "") { return }

    $datos = $linea -split ":"
    if ($datos.Count -ne 4) { return }

    $nombre, $apellido1, $apellido2, $login = $datos
    $usuario = Get-LocalUser -Name $login -ErrorAction SilentlyContinue
    Write-Host "fichero procesado"

    #salida de codigo controlada con -dry run

    if ($DryRun) {
        $fecha = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[DRY-RUN] $fecha - Se procesaría el usuario: $login ($nombre $apellido1 $apellido2)" -ForegroundColor Cyan
        Write-Host "[DRY-RUN] Se crearía la carpeta destino: C:\Users\proyecto\$login" -ForegroundColor Cyan
        Write-Host "[DRY-RUN] Se moverían los ficheros desde: C:\Users\$login\trabajo hacia C:\Users\proyecto\$login" -ForegroundColor Cyan
        Write-Host "[DRY-RUN] Se cambiaría el propietario de la carpeta a Administrador" -ForegroundColor Cyan
        Write-Host "[DRY-RUN] Se eliminaría el usuario $login y su perfil en C:\Users\$login" -ForegroundColor Cyan
        return
    }
    
    
    if (-not $usuario) {
        $fecha = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $motivo = "Usuario no existe"
        Write-Host "$fecha-$login-$nombre $apellido1 $apellido2-$motivo" -ForegroundColor Red
        return
    }

    # Crear carpeta destino
    $destino = "C:\Users\proyecto\$login"
    New-Item -ItemType Directory -Path $destino -Force | Out-Null

    # Directorio trabajo del usuario
    $trabajo = "C:\Users\$login\trabajo"
    if (Test-Path $trabajo) {
        $ficheros = Get-ChildItem $trabajo
        $contador = 0
        $listado = ""

        foreach ($f in $ficheros) {
            $contador++
            Move-Item $f.FullName -Destination $destino
            $listado += "$contador. $($f.Name)`n"
        }

        $fecha = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Add-Content $bajasLog "$fecha - $login - $destino`n$listado`nTotal: $contador`n"
        Write-Host ""
    }

    # Cambiar propietario de la carpeta a Administrador
    try {
        $acl = Get-Acl $destino
        $admin = New-Object System.Security.Principal.NTAccount("Administrador")
        $acl.SetOwner($admin)
        Set-Acl $destino $acl
        Write-Host "contenido de la carpeta $destino cambiado de dueño a administrador"
    } catch {
        Write-Host "Advertencia: No se pudo cambiar el propietario de $destino"
    }

    # Eliminar usuario y perfil
    try {
        Remove-LocalUser -Name $login
        Remove-Item "C:\Users\$login" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "el usuario $login se ha eliminado correctamente" -ForegroundColor Green
    } catch {
        Write-Host "Advertencia: No se pudo eliminar el usuario o su carpeta"
    }
}
