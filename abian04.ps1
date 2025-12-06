param([string]$ScriptPath)

$ErrorActionPreference='Stop'
$l="$env:SystemRoot\System32\LogFiles"
$bl="$l\bajas.log";$el="$l\bajaserror.log";$pr="C:\Users\proyecto"
$pwd=ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
$n=0;$e=@()
ri $bl,$el,$pr -EA 0
mkdir $l,$pr -Force|Out-Null

function V($c,$nm,$es,$ob){
if($c){$script:n++;Write-Host "✓ $nm" -F Green}
else{$script:e+="$nm : Esperado '$es', obtenido '$ob'"
Write-Host "✗ $nm" -F Red}}

function P($lg,$nom,$a1,$a2){try{
if(!(Get-LocalUser $lg -EA 0)){
New-LocalUser $lg -FullName "$nom $a1 $a2" -Password $pwd -PasswordNeverExpires|Out-Null}
$t="C:\Users\$lg\trabajo";mkdir $t -Force|Out-Null
sc "$t\archivo.txt" "x";sc "$t\documento.txt" "y"
mkdir "$t\subcarpeta" -Force|Out-Null
sc "$t\subcarpeta\archivo2.txt" "z"}catch{}}

function E($c,[switch]$d){
$f="$env:TEMP\bajas_test.txt";sc $f $c
try{$p=@{fichero=$f;ErrorAction='Stop'}
if($d){$p.DryRun=$true}
& $ScriptPath @p|Out-Null}catch{}
ri $f -EA 0}

Write-Host "`n=== PRUEBAS ===" -F Cyan

Write-Host "`n1: Eliminar usuario"
P dev1 Dev Uno Test;E "Dev:Uno:Test:dev1"
V (!(Get-LocalUser dev1 -EA 0)) "Usuario dev1 eliminado" "No existe" "Comprobado"

Write-Host "`n2: Mover archivos"
P dev2 Dev Dos Test;E "Dev:Dos:Test:dev2"
V (Test-Path "$pr\dev2\archivo.txt") "Archivo movido" "Existe" "Comprobado"

Write-Host "`n3: Log de bajas"
P dev3 Dev Tres Test;E "Dev:Tres:Test:dev3"
V ((gc $bl -EA 0) -match "dev3") "Entrada en bajas.log" "dev3" "Comprobado"

Write-Host "`n4: Log de errores"
E "No:Existe:Usuario:ghost1"
V ((gc $el -EA 0) -match "ghost1") "Entrada en bajaserror.log" "ghost1" "Comprobado"

Write-Host "`n5: Propietario Admin"
P dev5 Dev Cinco Test;E "Dev:Cinco:Test:dev5"
V ((Get-Acl "$pr\dev5").Owner -match "Administrador|Administrator") "Propietario Admin" "Admin" "Comprobado"

Write-Host "`n6: Directorio vacío"
P dev6 Dev Seis Test;ri "C:\Users\dev6\trabajo\*" -EA 0
E "Dev:Seis:Test:dev6"
V ((gc $bl -EA 0) -match "Total:\s*0") "Total 0 en log" "0" "Comprobado"

Write-Host "`n7: Parámetro inválido"
$f=$false;try{& $ScriptPath -fichero "C:\Windows" -EA Stop|Out-Null}catch{$f=$true}
V $f "Parámetro rechazado" "Error" "Comprobado"

Write-Host "`n8: Lote mixto"
P dev8 Dev Ocho Test;E "Dev:Ocho:Test:dev8`nNo:Existe:Usuario:ghost8"
V ((!(Get-LocalUser dev8 -EA 0)) -and ((gc $el -EA 0) -match "ghost8")) "Lote mixto procesado" "Ambos" "Comprobado"

Write-Host "`n9: Perfil eliminado"
P dev9 Dev Nueve Test;E "Dev:Nueve:Test:dev9"
V (!(Test-Path "C:\Users\dev9")) "Perfil eliminado" "No existe" "Comprobado"

Write-Host "`nPrueba 10: Modo dry-run"
P "dev10" "Dev" "Diez" "Test";$tf="$env:TEMP\bajas_dryrun.txt";sc $tf "Dev:Diez:Test:dev10"
try{& $ScriptPath -fichero $tf -DryRun|Out-Null}catch{};ri $tf -EA 0
V ((Get-LocalUser -Name "dev10" -EA 0) -ne $null) "Usuario intacto en dry-run" "Existe" "Existe"

Write-Host "`n=== RESULTADOS FINALES ===" -F Cyan
Write-Host "Nota: $n/10" -F $(if($n -eq 10){"Green"}else{"Yellow"})
if($e.Count -eq 0){Write-Host "✓ Todas las pruebas superadas" -F Green}
else{Write-Host "✗ Errores encontrados:" -F Red
$e|ForEach-Object{Write-Host "  - $_" -F Red}}
