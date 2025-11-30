param($Accion, [Parameter(ValueFromRemainingArguments=$true)]$Args, [switch]$DryRun)

if(!$Accion) {
    Write-Host "`nUSO: .\script.ps1 <Accion> <Parametros>`n" -f Yellow
    Write-Host "G  <Grupo> <Ambito> <Tipo>"
    Write-Host "U  <Usuario> <OU>"
    Write-Host "M  <Usuario> <Password> <habilitar|deshabilitar>"
    Write-Host "AG <Usuario> <Grupo>"
    Write-Host "LIST <Usuarios|Grupos|Ambos> [OU]"
    exit
}

# Crear grupo
function Crear-Grupo($nom,$amb="Global",$tip="Security") {
    $amb = switch -regex ($amb.ToLower()) {"uni"{"Universal"};"loc"{"DomainLocal"};default{"Global"}}
    $tip = if($tip -match "dist"){"Distribution"}else{"Security"}
    
    $obj = Get-ADObject -Filter "SamAccountName -eq '$nom'" -Properties objectClass -EA 0
    if($obj -and $obj.objectClass -eq 'group') {
        Write-Host "El grupo '$nom' ya existe" -f Yellow
        return
    }
    
    if($DryRun) {
        Write-Host "[DRY-RUN] Crearia grupo '$nom' [$amb/$tip]" -f Cyan
        return
    }
    
    $dn = (Get-ADDomain).DistinguishedName
    New-ADGroup -Name $nom -SamAccountName $nom -GroupScope $amb -GroupCategory $tip -Path "CN=Users,$dn"
    Write-Host "Grupo '$nom' creado [$amb/$tip]" -f Green
}

# Crear usuario
function Crear-Usuario($user,$ou) {
    $path = (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -EA 0).DistinguishedName
    if(!$path) {Write-Host "La OU '$ou' no existe" -f Red; return}
    
    $obj = Get-ADObject -Filter "SamAccountName -eq '$user'" -Properties objectClass -EA 0
    if($obj -and $obj.objectClass -eq 'user') {
        Write-Host "El usuario '$user' ya existe" -f Yellow
        return
    }
    
    if($DryRun) {
        Write-Host "[DRY-RUN] Crearia usuario '$user' en OU '$ou'" -f Cyan
        return
    }
    
    $pass = -join((48..122)|Get-Random -Count 12|%{[char]$_})
    $secpass = ConvertTo-SecureString $pass -AsPlainText -Force
    New-ADUser -Name $user -SamAccountName $user -Path $path -AccountPassword $secpass -Enabled $true
    Write-Host "Usuario '$user' creado en '$ou'. Pass: $pass" -f Green
}

# Modificar usuario
function Modificar-Usuario($u,$p,$estado) {
    if(!(Get-ADUser $u -EA 0)) {Write-Host "Usuario '$u' no existe" -f Red; return}
    
    # Validar contraseña
    if($p.Length -lt 8) {$msg="minimo 8 caracteres"}
    elseif($p -cnotmatch '[A-Z]') {$msg="falta mayuscula"}
    elseif($p -cnotmatch '[a-z]') {$msg="falta minuscula"}
    elseif($p -notmatch '\d') {$msg="falta numero"}
    elseif($p -notmatch '\W') {$msg="falta simbolo"}
    
    if($msg) {Write-Host "Password invalida: $msg" -f Red; return}
    
    if($DryRun) {
        Write-Host "[DRY-RUN] Cambiaria password de '$u' y estado '$estado'" -f Cyan
        return
    }
    
    Set-ADAccountPassword -Identity $u -NewPassword (ConvertTo-SecureString $p -AsPlainText -Force) -Reset
    Write-Host "Password cambiada" -f Green
    
    switch -regex($estado.ToLower()) {
        'hab|ena' {Enable-ADAccount $u; Write-Host "Cuenta habilitada" -f Green}
        'des|dis' {Disable-ADAccount $u; Write-Host "Cuenta deshabilitada" -f Yellow}
        default {Write-Host "Estado no valido" -f Yellow}
    }
}

# Agregar a grupo
function Agregar-Grupo($usr,$grp) {
    $user = Get-ADUser $usr -EA 0
    $grupo = Get-ADGroup $grp -EA 0
    
    if(!$user) {Write-Host "Usuario '$usr' no existe" -f Red; return}
    if(!$grupo) {Write-Host "Grupo '$grp' no existe" -f Red; return}
    
    if($DryRun) {
        Write-Host "[DRY-RUN] Agregaria '$usr' a '$grp'" -f Cyan
        return
    }
    
    Add-ADGroupMember -Identity $grp -Members $usr -EA 0
    Write-Host "Usuario '$usr' agregado a '$grp'" -f Green
}

# Listar objetos
function Listar($tipo,$ou) {
    if($DryRun) {Write-Host "[DRY-RUN] Listaria '$tipo'" -f Cyan; return}
    
    switch($tipo.ToLower()) {
        "usuarios" {
            if($ou) {Get-ADUser -SearchBase $ou -Filter * | Select Name,SamAccountName}
            else {Get-ADUser -Filter * | Select Name,SamAccountName}
        }
        "grupos" {
            if($ou) {Get-ADGroup -SearchBase $ou -Filter * | Select Name,GroupScope,GroupCategory}
            else {Get-ADGroup -Filter * | Select Name,GroupScope,GroupCategory}
        }
        "ambos" {
            Get-ADGroup -Filter * | % {
                Write-Host "`nGrupo: $($_.Name)" -f Cyan
                Get-ADGroupMember $_ | ? {$_.objectClass -eq 'user'} | Select -ExpandProperty Name
            }
        }
        default {Write-Host "Tipo no valido. Usa: Usuarios, Grupos o Ambos" -f Red}
    }
}

# Ejecutar accion
switch($Accion.ToUpper()) {
    "G"    {Crear-Grupo $Args[0] $Args[1] $Args[2]}
    "U"    {Crear-Usuario $Args[0] $Args[1]}
    "M"    {Modificar-Usuario $Args[0] $Args[1] $Args[2]}
    "AG"   {Agregar-Grupo $Args[0] $Args[1]}
    "LIST" {Listar $Args[0] $Args[1]}
    default {Write-Host "Accion '$Accion' no valida. Usa: G, U, M, AG, LIST" -f Red}
}