param(
    [Parameter(Position=0)]
    [string]$Accion,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ArgsExtra,

    [switch]$DryRun  # ← nuevo parámetro
)


# Si no se pasa ninguna acción, mostrar ayuda y salir
if (-not $Accion) {
    Write-Host "`n No se ha especificado ninguna acción.`n"
    Write-Host "USO: .\abian02.ps1 <Acción> <Parámetros>`n"
    Write-Host "Acciones disponibles:`n"
    Write-Host "  G    <NombreGrupo> <Ámbito: Global|Universal|Local> <Tipo: Seguridad|Distribución>"
    Write-Host "  U    <NombreUsuario> <UO>"
    Write-Host "  M    <NombreUsuario> <NuevaContraseña> <Estado: habilitar|deshabilitar>"
    Write-Host "  AG   <NombreUsuario> <NombreGrupo>"
    Write-Host "  LIST <Usuarios|Grupos|Ambos> [UnidadOrganizativa]"
    exit
}


if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host " El módulo 'ActiveDirectory' no está instalado."
    Write-Host "Instálalo con: Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'"
    exit
}

Import-Module ActiveDirectory -ErrorAction Stop


function Crear-Grupo {
    param($Nombre, $Ambito="Global", $Tipo="Security")
    $Ambito = switch -regex ($Ambito.ToLower()) { "uni"{"Universal"};"loc|dom"{"DomainLocal"};default{"Global"} }
    $Tipo   = if ($Tipo -match "dist") {"Distribution"} else {"Security"}
    $dn = (Get-ADDomain).DistinguishedName

    #Verificar si ya existe un objeto con ese nombre y si es grupo o usuario
    $obj = Get-ADObject -Filter "SamAccountName -eq '$Nombre'" -Properties objectClass -ErrorAction SilentlyContinue
    if ($obj -and $obj.objectClass -eq 'group') {
        Write-Host " El grupo '$Nombre' ya existe, elige otro nombre." -ForegroundColor Yellow
        return
    }

    if ($DryRun) {
    Write-Host "[DRY-RUN] Se crearía el grupo '$Nombre' con ámbito '$Ambito' y tipo '$Tipo' en CN=Users,$dn" -ForegroundColor Cyan
    return
    }

    # Si existe un usuario con el mismo nombre, no pasa nada → puede crear el grupo
    New-ADGroup -Name $Nombre -SamAccountName $Nombre -GroupScope $Ambito -GroupCategory $Tipo -Path "CN=Users,$dn"
    Write-Host " Grupo '$Nombre' creado [$Ambito/$Tipo]" -ForegroundColor Green

    
}

function Crear-Usuario {
    param($NombreUsuario, $NombreOU)
    $OU = (Get-ADOrganizationalUnit -Filter "Name -eq '$NombreOU'" -EA SilentlyContinue).DistinguishedName
    if (-not $OU) { Write-Host " La OU '$NombreOU' no existe." -ForegroundColor Red; return }

    # Verificar si existe un objeto con ese nombre
    $obj = Get-ADObject -Filter "SamAccountName -eq '$NombreUsuario'" -Properties objectClass -EA SilentlyContinue
    if ($obj -and $obj.objectClass -eq 'user') {
        Write-Host " El usuario '$NombreUsuario' ya existe." -ForegroundColor Yellow
        return
    }

    if ($DryRun) {
    Write-Host "[DRY-RUN] Se crearía el usuario '$NombreUsuario' en la OU '$NombreOU' con una contraseña aleatoria." -ForegroundColor Cyan
    return
    }

    # Si existe un grupo con el mismo nombre, se crea igualmente
    $pwd = -join ((48..122) | Get-Random -Count 12 | % {[char]$_})
    $spwd = ConvertTo-SecureString $pwd -AsPlainText -Force
    New-ADUser -Name $NombreUsuario -SamAccountName $NombreUsuario -Path $OU -AccountPassword $spwd -Enabled $true
    Write-Host "Usuario '$NombreUsuario' creado en '$NombreOU' con contraseña: $pwd" -ForegroundColor Green
}


function Modificar-Usuario {
    param($u,$p,$e)
    if(-not($x=Get-ADUser -Identity $u -EA 0)){Write-Host " Usuario '$u' no existe." -f Red;return}
    if($p.Length -lt 8){$m="mínimo 8 caracteres"}
    elseif($p -cnotmatch '[A-Z]'){$m="falta una mayúscula"}
    elseif($p -cnotmatch '[a-z]'){$m="falta una minúscula"}
    elseif($p -notmatch '\d'){$m="falta un número"}
    elseif($p -notmatch '\W'){$m="falta un símbolo"}
    if($m){Write-Host " Contraseña inválida ($m)." -f Red;return}
    
    if ($DryRun) {
    Write-Host "[DRY-RUN] Se cambiaría la contraseña del usuario '$u' y se aplicaría el estado '$e'." -ForegroundColor Cyan
    return
    }

    Set-ADAccountPassword -Identity $u -NewPassword (ConvertTo-SecureString $p -AsPlainText -Force) -Reset
    Write-Host " Contraseña cambiada." -f Green
    switch -regex($e.ToLower()){
        'hab|ena'{Enable-ADAccount -Identity $u;Write-Host " Cuenta habilitada." -f Green}
        'des|dis'{Disable-ADAccount -Identity $u;Write-Host " Cuenta deshabilitada." -f Yellow}
        default{Write-Host " Estado no reconocido (usa enable/disable)." -f Yellow}
    }
}

function Agregar-A-Grupo ($Usuario, $Grupo) {
    $user = Get-ADUser -Identity $Usuario -ErrorAction SilentlyContinue
    $group = Get-ADGroup -Identity $Grupo -ErrorAction SilentlyContinue

    if (-not $user) { Write-Host " Usuario '$Usuario' no existe." -ForegroundColor Red; return }
    if (-not $group) { Write-Host " Grupo '$Grupo' no existe." -ForegroundColor Red; return }

    if ($DryRun) {
    Write-Host "[DRY-RUN] Se agregaría el usuario '$Usuario' al grupo '$Grupo'." -ForegroundColor Cyan
    return
    }

    Add-ADGroupMember -Identity $Grupo -Members $Usuario
    Write-Host " Usuario '$Usuario' agregado al grupo '$Grupo'." -ForegroundColor Green
}

function Listar-Objetos ($Tipo, $OU) {
    
    if ($DryRun) {
        Write-Host "[DRY-RUN] Se listarían los objetos de tipo '$Tipo'." -ForegroundColor Cyan
        return
    }

    switch ($Tipo.ToLower()) {
        "usuarios" {
            if ($OU) { Get-ADUser -SearchBase $OU -Filter * | Select Name, SamAccountName }
            else { Get-ADUser -Filter * | Select Name, SamAccountName }
        }
        "grupos" {
            if ($OU) { Get-ADGroup -SearchBase $OU -Filter * | Select Name, GroupScope, GroupCategory }
            else { Get-ADGroup -Filter * | Select Name, GroupScope, GroupCategory }
        }
        "ambos" {
            Get-ADGroup -Filter * | ForEach-Object {
            Write-Host "`n Grupo:" $_.Name -ForegroundColor Cyan
            Get-ADGroupMember $_ | Where-Object {$_.objectClass -eq 'user'} | Select-Object -ExpandProperty Name
        }
        }
        default { Write-Host " Tipo no válido. Usa: Usuarios, Grupos o Ambos." -ForegroundColor Red }
    }
}


switch ($Accion.ToUpper()) {
    "G"    { Crear-Grupo $ArgsExtra[0] $ArgsExtra[1] $ArgsExtra[2] }
    "U"    { Crear-Usuario $ArgsExtra[0] $ArgsExtra[1] }
    "M"    { Modificar-Usuario $ArgsExtra[0] $ArgsExtra[1] $ArgsExtra[2] }
    "AG"   { Agregar-A-Grupo $ArgsExtra[0] $ArgsExtra[1] }
    "LIST" { Listar-Objetos $ArgsExtra[0] $ArgsExtra[1] }
    default {
        Write-Host " Acción '$Accion' no reconocida.`n" -ForegroundColor Red
        Write-Host "Usa una de las siguientes acciones válidas:" -ForegroundColor Yellow
        Write-Host "  G, U, M, AG, LIST" -ForegroundColor Cyan
    }
}
