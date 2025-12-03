param($Accion, [Parameter(ValueFromRemainingArguments=$true)]$Args, [switch]$DryRun)

if(!$Accion) {
    Write-Host "`nDebe añadir parámetros para usar la función.`n" -f Yellow
    Write-Host "Acciones disponibles:`n"
    Write-Host "-G  <Nombre> <Ámbito> <Tipo> - Crea un grupo"
    Write-Host "-U  <Nombre> <Usuario> <UO> - Crea un usuario"
    Write-Host "-M  <Usuario> <Password> <habilitar|deshabilitar> - Modifica usuario"
    Write-Host "-AG <Usuario> <Grupo> - Asigna usuario a grupo"
    Write-Host "-LIST <Usuarios|Grupos|Ambos> [UO] - Lista objetos`n"
    exit
}

function Crear-Grupo($nom,$amb,$tip) {
    $ambito = switch -regex ($amb.ToLower()) {"uni"{"Universal"};"loc"{"DomainLocal"};default{"Global"}}
    $tipo = if($tip -match "dist"){"Distribution"}else{"Security"}
    
    if(Get-ADGroup -Filter "Name -eq '$nom'" -EA 0) {Write-Host "El grupo ya está creado" -f Yellow; return}
    if($DryRun) {Write-Host "[DRY-RUN] Crearía grupo '$nom' [$ambito/$tipo]" -f Cyan; return}
    
    New-ADGroup -Name $nom -SamAccountName $nom -GroupScope $ambito -GroupCategory $tipo -Path "CN=Users,$((Get-ADDomain).DistinguishedName)"
    Write-Host "Grupo '$nom' creado [$amb/$tip]" -f Green
}

function Crear-Usuario($nombre,$user,$ou) {
    $path = (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -EA 0).DistinguishedName
    if(!$path) {Write-Host "La UO '$ou' no existe" -f Red; return}
    if(Get-ADUser -Filter "SamAccountName -eq '$user'" -EA 0) {Write-Host "El usuario ya existe" -f Yellow; return}
    if($DryRun) {Write-Host "[DRY-RUN] Crearía usuario '$user' en '$ou'" -f Cyan; return}
    
    $pass = -join((48..57)+(65..90)+(97..122)+(33,35,36,37,38,42,43,45,61,63,64)|Get-Random -Count 12|%{[char]$_})
    New-ADUser -Name $nombre -SamAccountName $user -Path $path -AccountPassword (ConvertTo-SecureString $pass -AsPlainText -Force) -Enabled $true
    Write-Host "Usuario '$user' creado. Contraseña: $pass" -f Green
}

function Modificar-Usuario($u,$p,$estado) {
    if(!(Get-ADUser -Filter "SamAccountName -eq '$u'" -EA 0)) {Write-Host "El usuario no existe" -f Red; return}
    
    $motivo = if($p.Length -lt 8){"debe tener mínimo 8 caracteres"}
              elseif($p -cnotmatch '[A-Z]'){"debe contener al menos una mayúscula"}
              elseif($p -cnotmatch '[a-z]'){"debe contener al menos una minúscula"}
              elseif($p -notmatch '\d'){"debe contener al menos un número"}
              elseif($p -notmatch '[^a-zA-Z0-9]'){"debe contener al menos un carácter especial"}
    
    if($motivo) {Write-Host "Error: La contraseña no es válida. Motivo: $motivo" -f Red; return}
    if($DryRun) {Write-Host "[DRY-RUN] Modificaría '$u' y estado '$estado'" -f Cyan; return}
    
    Set-ADAccountPassword -Identity $u -NewPassword (ConvertTo-SecureString $p -AsPlainText -Force) -Reset
    Write-Host "Contraseña modificada correctamente" -f Green
    
    switch -regex($estado.ToLower()) {
        'hab|ena' {Enable-ADAccount $u; Write-Host "Cuenta habilitada" -f Green}
        'des|dis' {Disable-ADAccount $u; Write-Host "Cuenta deshabilitada" -f Yellow}
        default {Write-Host "Estado no válido" -f Red}
    }
}

function Agregar-Grupo($usr,$grp) {
    if(!(Get-ADUser -Filter "SamAccountName -eq '$usr'" -EA 0)) {Write-Host "Error: El usuario no existe" -f Red; return}
    if(!(Get-ADGroup -Filter "Name -eq '$grp'" -EA 0)) {Write-Host "Error: El grupo no existe" -f Red; return}
    if($DryRun) {Write-Host "[DRY-RUN] Asignaría '$usr' a '$grp'" -f Cyan; return}
    
    Add-ADGroupMember -Identity $grp -Members $usr -EA 0
    Write-Host "Asignación realizada correctamente" -f Green
}

function Listar($tipo,$ou) {
    if($DryRun) {Write-Host "[DRY-RUN] Listaría '$tipo'" -f Cyan; return}
    
    $sb = if($ou){(Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -EA 0).DistinguishedName}
    if($ou -and !$sb) {Write-Host "La UO '$ou' no existe" -f Red; return}
    
    switch($tipo.ToLower()) {
        "usuarios" {
            if($sb) {Get-ADUser -SearchBase $sb -Filter * | Select Name,SamAccountName | Sort Name}
            else {Get-ADUser -Filter * | Select Name,SamAccountName | Sort Name}
        }
        "grupos" {
            if($sb) {Get-ADGroup -SearchBase $sb -Filter * | Select Name,GroupScope,GroupCategory | Sort Name}
            else {Get-ADGroup -Filter * | Select Name,GroupScope,GroupCategory | Sort Name}
        }
        "ambos" {
            Write-Host "`n=== USUARIOS ===" -f Cyan
            if($sb) {Get-ADUser -SearchBase $sb -Filter * | Select Name,SamAccountName | Sort Name | Format-Table -AutoSize}
            else {Get-ADUser -Filter * | Select Name,SamAccountName | Sort Name | Format-Table -AutoSize}
            Write-Host "`n=== GRUPOS ===" -f Cyan
            if($sb) {Get-ADGroup -SearchBase $sb -Filter * | Select Name,GroupScope,GroupCategory | Sort Name | Format-Table -AutoSize}
            else {Get-ADGroup -Filter * | Select Name,GroupScope,GroupCategory | Sort Name | Format-Table -AutoSize}
        }
        default {Write-Host "Tipo no válido. Use: Usuarios, Grupos o Ambos" -f Red}
    }
}

switch($Accion.ToUpper()) {
    "G"    {Crear-Grupo $Args[0] $Args[1] $Args[2]}
    "U"    {Crear-Usuario $Args[0] $Args[1] $Args[2]}
    "M"    {Modificar-Usuario $Args[0] $Args[1] $Args[2]}
    "AG"   {Agregar-Grupo $Args[0] $Args[1]}
    "LIST" {Listar $Args[0] $Args[1]}
    default {Write-Host "Acción no válida. Use: -G, -U, -M, -AG, -LIST" -f Red}
}
