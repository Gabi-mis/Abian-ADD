param([Parameter(Mandatory=$true)][string]$fichero,[switch]$DryRun)

$parametrosRecibidos = @($fichero).Count
if ($parametrosRecibidos -gt 1 -or !(Test-Path $fichero -ErrorAction SilentlyContinue) -or (Get-Item $fichero -ErrorAction SilentlyContinue).PSIsContainer) {
    $fecha = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content $errorLog "$fecha - Error: Se debe pasar un único fichero válido como parámetro. Parámetros recibidos: $fichero"
    Write-Host "$fecha - Error: Se debe pasar un único fichero válido como parámetro. Parámetros recibidos: $fichero" -ForegroundColor Yellow
    exit
}

$logDir = "$env:SystemRoot\System32\LogFiles"
$bajasLog = "$logDir\bajas.log"
$errorLog = "$logDir\bajaserror.log"

Get-Content $fichero | ForEach-Object {
    $linea = $_.Trim()
    if(!$linea -or ($linea -split ":").Count -ne 4) {return}
    $nombre,$apellido1,$apellido2,$login = $linea -split ":"
    $usuario = Get-LocalUser -Name $login -EA 0
    $fecha = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    if($DryRun) {
        Write-Host "[DRY-RUN] $fecha - Usuario: $login ($nombre $apellido1 $apellido2)" -f Cyan
        Write-Host "[DRY-RUN] Carpeta: C:\Users\proyecto\$login | Origen: C:\Users\$login\trabajo" -f Cyan
        Write-Host "[DRY-RUN] Propietario: Administrador | Eliminación: Usuario y perfil" -f Cyan
        return
    }
    
    if(!$usuario) {
        Add-Content $errorLog "$fecha - $login - $nombre $apellido1 $apellido2 - Usuario no existe"
        return
    }
    
    $destino = "C:\Users\proyecto\$login"
    New-Item -ItemType Directory -Path $destino -Force | Out-Null
    $trabajo = "C:\Users\$login\trabajo"
    
    if(Test-Path $trabajo) {
        $contador = 0; $listado = ""
        Get-ChildItem $trabajo | ForEach-Object {
            $contador++
            Move-Item $_.FullName -Destination $destino -EA 0
            $listado += "$contador. $($_.Name)`n"
        }
        Add-Content $bajasLog "$fecha - $login - $destino`n$listado`nTotal: $contador`n"
    }
    
    try {
        $acl = Get-Acl $destino
        $acl.SetOwner((New-Object System.Security.Principal.NTAccount("Administrador")))
        Set-Acl $destino $acl
        Write-Host "Propietario de $destino cambiado a Administrador" -f Green
    } catch {
        Add-Content $errorLog "$fecha - $login - $nombre $apellido1 $apellido2 - Error cambio propietario"
    }
    
    try {
        Remove-LocalUser -Name $login
        Remove-Item "C:\Users\$login" -Recurse -Force -EA 0
        Write-Host "Usuario $login eliminado correctamente" -f Green
    } catch {
        Add-Content $errorLog "$fecha - $login - $nombre $apellido1 $apellido2 - Error eliminación"
    }
}
