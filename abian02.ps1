param($Accion, [Parameter(ValueFromRemainingArguments=$true)]$Args)

if(!$Accion) {
    Write-Host "`nDebe añadir parámetros.`n" -f Yellow
    "G <Nombre> <Ámbito> <Tipo>","U <Nombre> <Usuario> <UO>","M <Usuario> <Pass> <hab|des>" | %{Write-Host "-$_"}
    "AG <Usuario> <Grupo>","LIST <Usuarios|Grupos|Ambos> [UO]" | %{Write-Host "-$_"}
    exit
}

function Crear-Grupo($n,$a,$t) {
    $amb = if($a -match "uni"){"Universal"}elseif($a -match "loc"){"DomainLocal"}else{"Global"}
    $tip = if($t -match "dist"){"Distribution"}else{"Security"}
    if(Get-ADGroup -Filter "Name -eq '$n'" -EA 0) {Write-Host "El grupo ya está creado" -f Yellow; return}
    New-ADGroup -Name $n -SamAccountName $n -GroupScope $amb -GroupCategory $tip -Path "CN=Users,$((Get-ADDomain).DistinguishedName)"
    Write-Host "Grupo '$n' creado [$amb/$tip]" -f Green
}

function Crear-Usuario($nom,$u,$ou) {
    $path = (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -EA 0).DistinguishedName
    if(!$path) {Write-Host "La UO '$ou' no existe" -f Red; return}
    if(Get-ADUser -Filter "SamAccountName -eq '$u'" -EA 0) {Write-Host "El usuario ya existe" -f Yellow; return}
    $pw = -join((48..57+65..90+97..122+33,35,36,37,38,42,43,45,61,63,64)|Get-Random -C 12|%{[char]$_})
    New-ADUser -Name $nom -SamAccountName $u -Path $path -AccountPassword (ConvertTo-SecureString $pw -AsPlainText -Force) -Enabled $true
    Write-Host "Usuario '$u' creado. Contraseña: $pass" -f Green
}

function Modificar-Usuario($u,$pw,$e) {
    if(!(Get-ADUser -Filter "SamAccountName -eq '$u'" -EA 0)) {Write-Host "Usuario no existe" -f Red; return}
    $m = if($pw.Length -lt 8){"debe tener mínimo 8 caracteres"}elseif($pw -cnotmatch '[A-Z]'){"debe contener al menos una mayúscula"}
    elseif($pw -cnotmatch '[a-z]'){"debe contener al menos una minúscula"}elseif($pw -notmatch '\d'){"debe contener al menos un número"}
    elseif($pw -notmatch '[^a-zA-Z0-9]'){"debe contener al menos un carácter especial"}
    if($m) {Write-Host "Error: La contraseña no es válida. Motivo: $m" -f Red; return}
    Set-ADAccountPassword -Identity $u -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force) -Reset
    Write-Host "Contraseña modificada correctamente" -f Green
    if($e -match "hab") {Enable-ADAccount $u; Write-Host "Cuenta habilitada" -f Green}
    elseif($e -match "des") {Disable-ADAccount $u; Write-Host "Cuenta Deshabilitada" -f Yellow}
}

function Agregar-Grupo($usr,$grp) {
    if(!(Get-ADUser -Filter "SamAccountName -eq '$usr'" -EA 0)) {Write-Host "Error: El usuario no existe" -f Red; return}
    if(!(Get-ADGroup -Filter "Name -eq '$grp'" -EA 0)) {Write-Host "Error: El grupo no existe" -f Red; return}
    Add-ADGroupMember -Identity $grp -Members $usr -EA 0
    Write-Host "Asignación realizada correctamente" -f Green
}

function Listar($tipo,$ou) {
    $sb = if($ou){(Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -EA 0).DistinguishedName}
    if($ou -and !$sb) {Write-Host "UO no existe" -f Red; return}
    $f = if($sb){@{SearchBase=$sb}}else{@{}}
    switch($tipo.ToLower()) {
        "usuarios" {Get-ADUser @f -Filter *|Select Name,SamAccountName|Sort Name}
        "grupos" {Get-ADGroup @f -Filter *|Select Name,GroupScope,GroupCategory|Sort Name}
        "ambos" {
            Write-Host "`n=== USUARIOS ===" -f Cyan
            Get-ADUser @f -Filter *|Select Name,SamAccountName|Sort Name|ft -Auto
            Write-Host "`n=== GRUPOS ===" -f Cyan
            Get-ADGroup @f -Filter *|Select Name,GroupScope,GroupCategory|Sort Name|ft -Auto
        }
    }
}

switch($Accion.ToUpper()) {
    "G" {Crear-Grupo $Args[0] $Args[1] $Args[2]}
    "U" {Crear-Usuario $Args[0] $Args[1] $Args[2]}
    "M" {Modificar-Usuario $Args[0] $Args[1] $Args[2]}
    "AG" {Agregar-Grupo $Args[0] $Args[1]}
    "LIST" {Listar $Args[0] $Args[1]}
}

