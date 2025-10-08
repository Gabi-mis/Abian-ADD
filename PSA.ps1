1. Ver uso de CPU y memoria del sistema
# Monitorear CPU y memoria
$cpu = Get-Counter '\Processor(_Total)\% Processor Time'
$ram = Get-WmiObject Win32_OperatingSystem
Write-Host "Uso de CPU: $($cpu.CounterSamples.CookedValue)%"
Write-Host "Memoria libre: $([math]::Round($ram.FreePhysicalMemory / 1024)) MB"
Write-Host "Memoria total: $([math]::Round($ram.TotalVisibleMemorySize / 1024)) MB"

🧩 2. Listar servicios que están detenidos
# Mostrar servicios detenidos
$stopped = Get-Service | Where-Object {$_.Status -eq 'Stopped'}
$stopped | Select-Object Name, DisplayName
Write-Host "Servicios detenidos: $($stopped.Count)"

🧩 3. Reiniciar automáticamente un servicio si está detenido
# Reiniciar servicio crítico
$service = Get-Service -Name "Spooler"
if ($service.Status -ne 'Running') {
    Restart-Service -Name "Spooler"
    Write-Host "Servicio Spooler reiniciado."
} else {
    Write-Host "El servicio Spooler ya está activo."
}

🧩 4. Crear un usuario local con contraseña
# Crear usuario local
$User = "AdminTemp"
$Password = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
New-LocalUser $User -Password $Password -FullName "Admin Temporal"
Add-LocalGroupMember -Group "Administrators" -Member $User
Write-Host "Usuario $User creado con privilegios de administrador."

🧩 5. Comprobar conectividad a una lista de servidores
# Probar conexión a servidores
$servers = @("DC01","DB01","WEB01")
foreach ($s in $servers) {
    if (Test-Connection $s -Count 1 -Quiet) {
        Write-Host "$s responde al ping."
    } else {
        Write-Host "$s no responde." -ForegroundColor Red
    }
}

🧩 6. Limpiar archivos temporales del sistema
# Limpiar temporales
$temp = "$env:TEMP\*"
Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Archivos temporales eliminados en $env:TEMP"

🧩 7. Mostrar usuarios conectados actualmente
# Mostrar usuarios activos
$query = quser 2>$null
if ($query) {
    Write-Host "Usuarios conectados:"; $query
} else {
    Write-Host "No hay sesiones activas."
}

🧩 8. Generar un log diario del uso del disco
# Crear log de disco
$fecha = Get-Date -Format "yyyy-MM-dd_HH-mm"
$disco = Get-PSDrive C
"$fecha - C: Usado=$($disco.Used/1GB)GB Libre=$($disco.Free/1GB)GB" |
Out-File "C:\Logs\DiscoLog.txt" -Append

🧩 9. Detener procesos que consumen mucha CPU
# Detener procesos que usan >80% CPU
Get-Process | Where-Object { $_.CPU -gt 80 } | ForEach-Object {
    Stop-Process -Id $_.Id -Force
    Write-Host "Proceso detenido: $($_.Name)"
}

🧩 10. Programar un reinicio automático
# Programar reinicio
$hora = (Get-Date).AddMinutes(5)
schtasks /create /sc once /tn "ReinicioServer" /tr "shutdown /r /t 0" /st $hora.ToString("HH:mm")
Write-Host "Reinicio programado a las $hora"

1.01 Listar usuarios locales y sus grupos
# 1.01 - Listar usuarios locales y grupos
Get-LocalUser | ForEach-Object {
    $user = $_.Name
    $groups = Get-LocalGroup | Where-Object { (Get-LocalGroupMember $_.Name -ErrorAction SilentlyContinue).Name -contains $user } |
        Select-Object -ExpandProperty Name
    [PSCustomObject]@{ Usuario = $user; Grupos = ($groups -join ", ") }
} | Format-Table -AutoSize

1.02 Crear usuario con expiración de contraseña
# 1.02 - Crear usuario local con expiración de contraseña
$User = "tempUser01"
$Pwd = ConvertTo-SecureString "TempP@ssw0rd!" -AsPlainText -Force
New-LocalUser -Name $User -Password $Pwd -PasswordNeverExpires $false -AccountNeverExpires $false
Write-Host "Usuario $User creado. Configure políticas de contraseña según convenga."

1.03 Habilitar o deshabilitar un usuario local
# 1.03 - Habilitar o deshabilitar usuario
param($UserName="tempUser01",$Enable=$false)
$user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if ($user) {
    if ($Enable) { Enable-LocalUser -Name $UserName } else { Disable-LocalUser -Name $UserName }
    Write-Host "Usuario $UserName actualizado. Habilitado=$Enable"
} else { Write-Host "Usuario no encontrado: $UserName" }

1.04 Listar servicios esenciales y su estado
# 1.04 - Servicios esenciales
$serviceNames = @("LanmanServer","LanmanWorkstation","WinRM","W32Time","Spooler")
Get-Service -Name $serviceNames -ErrorAction SilentlyContinue |
    Select-Object Name,DisplayName,Status | Format-Table -AutoSize

1.05 Reiniciar servicio y registrar resultado
# 1.05 - Reiniciar servicio y registrar en archivo
$svc = "Spooler"
Try {
    Restart-Service -Name $svc -Force -ErrorAction Stop
    "$((Get-Date).ToString()) - Servicio $svc reiniciado correctamente." | Out-File C:\Logs\ServiceActions.log -Append
} Catch {
    "$((Get-Date).ToString()) - Error reiniciando $svc: $_" | Out-File C:\Logs\ServiceActions.log -Append
}

1.06 Matar procesos por nombre con confirmación
# 1.06 - Matar procesos por nombre
param($ProcessName="notepad")
$procs = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
if ($procs) {
    $procs | ForEach-Object { Stop-Process -Id $_.Id -Force; Write-Host "Proceso detenido: $($_.Name) ($($_.Id))" }
} else { Write-Host "No se encontraron procesos: $ProcessName" }

1.07 Monitor de procesos que consumen más memoria
# 1.07 - Top 10 procesos por uso de memoria
Get-Process | Sort-Object -Property WS -Descending | Select-Object -First 10 Name,Id,@{n='MemMB';e={[math]::Round($_.WS/1MB,2)}} |
    Format-Table -AutoSize

1.08 Programar tarea simple con schtasks
# 1.08 - Programar tarea para ejecutar script
$taskName = "Tarea_Limpieza_Temp"
$scriptPath = "C:\Scripts\LimpiaTemp.ps1"
schtasks /create /sc daily /tn $taskName /tr "powershell -ExecutionPolicy Bypass -File `"$scriptPath`"" /st 03:00
Write-Host "Tarea $taskName creada para $scriptPath"

1.09 Mostrar espacio en disco y alerta si <20%
# 1.09 - Alertar discos con menos del 20% libre
Get-PSDrive -PSProvider FileSystem | ForEach-Object {
    $pct = [math]::Round(($_.Free / $_.Used*100),2) 2>$null
    if ($pct -eq 0) { $pct = [math]::Round(($_.Free / ($_.Free + $_.Used) * 100),2) }
    if ($pct -lt 20) { Write-Host "ALERTA: $_.Name tiene menos del 20% libre." -ForegroundColor Red }
    else { Write-Host "$($_.Name): $pct% libre" }
}

1.10 Exportar lista de tareas programadas
# 1.10 - Exportar tareas programadas a CSV
schtasks /query /fo LIST /v | Out-String -Stream | Where-Object { $_ -match "TaskName|Scheduled Task State|Next Run Time" } |
    Set-Content C:\Logs\ScheduledTasksRaw.txt
Write-Host "Listado de tareas programadas exportado a C:\Logs\ScheduledTasksRaw.txt"

Redes y conectividad
2.01 Hacer ping a una lista y exportar resultados
# 2.01 - Ping a lista de hosts
$hosts = @("8.8.8.8","google.com","intranet")
$results = foreach ($h in $hosts) {
    [PSCustomObject]@{ Host = $h; Reachable = Test-Connection $h -Count 2 -Quiet }
}
$results | Export-Csv C:\Logs\PingResults.csv -NoTypeInformation

2.02 Obtener adaptadores de red y su configuración IP
# 2.02 - Adaptadores y configuración IP
Get-NetAdapter | ForEach-Object {
    $if = $_.Name
    $ips = Get-NetIPAddress -InterfaceAlias $if -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Select-Object IPAddress,PrefixLength
    [PSCustomObject]@{ Interface = $if; Estado = $_.Status; IPs = ($ips.IPAddress -join ", ") }
} | Format-Table -AutoSize

2.03 Flush DNS y renovar IP
# 2.03 - Flush DNS y renovar DHCP
ipconfig /flushdns
Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
    Write-Host "Renovando DHCP en $($_.Name)"
    ipconfig /release *> $null
    ipconfig /renew *> $null
}
Write-Host "Operación completada."

2.04 Comprobar puertos remotos con Test-NetConnection
# 2.04 - Probar puerto remoto
param($Host="example.com",$Port=443)
$res = Test-NetConnection -ComputerName $Host -Port $Port -WarningAction SilentlyContinue
$res | Select-Object ComputerName,RemoteAddress,RemotePort,TcpTestSucceeded | Format-List

2.05 Listar rutas activas
# 2.05 - Mostrar tabla de rutas IPv4
Get-NetRoute -AddressFamily IPv4 | Select-Object ifIndex,DestinationPrefix,NextHop,RouteMetric |
    Sort-Object DestinationPrefix | Format-Table -AutoSize

2.06 Hacer traceroute y guardar resultado
# 2.06 - Traceroute con tracert
param($Host="8.8.8.8")
tracert $Host | Out-File C:\Logs\TraceRoute_$((Get-Date).ToString("yyyyMMdd_HHmmss")).txt
Write-Host "Traceroute guardado."

2.07 Habilitar/deshabilitar interfaz de red
# 2.07 - Cambiar estado de adaptador
param($IfName="Ethernet",$Enable=$false)
if ($Enable) { Enable-NetAdapter -Name $IfName -Confirm:$false } else { Disable-NetAdapter -Name $IfName -Confirm:$false }
Write-Host "Interfaz $IfName - Habilitada=$Enable"

2.08 Monitor de latencia a un host
# 2.08 - Monitoreo de latencia continuo (5 pings)
param($Host="8.8.8.8")
1..5 | ForEach-Object {
    $r = Test-Connection -Count 1 -ComputerName $Host
    "{0} - {1} ms" -f (Get-Date -Format O), $r.ResponseTime
    Start-Sleep -Seconds 1
}

2.09 Mostrar tabla ARP
# 2.09 - Tabla ARP
arp -a | Out-String | Write-Host

2.10 Diagnóstico básico de red y resumen
# 2.10 - Resumen de conectividad
$host = "8.8.8.8"
$ping = Test-Connection $host -Count 2 -Quiet
$dns = Resolve-DnsName "google.com" -ErrorAction SilentlyContinue
[PSCustomObject]@{ PingOK = $ping; DNSOK = ($dns -ne $null); Time = Get-Date } | Format-List

Seguridad y auditoría
3.01 Obtener últimos eventos de seguridad (ID 4624, 4625)
# 3.01 - Eventos de inicio de sesión exitosos/failed
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4624,4625); StartTime=(Get-Date).AddDays(-1)} -MaxEvents 100 |
    Select-Object TimeCreated,Id,Message | Out-File C:\Logs\SecurityEvents_Last24h.txt
Write-Host "Eventos de seguridad exportados."

3.02 Revisar cuentas con contraseña expirada
# 3.02 - Usuarios locales con contraseña expirada (approx)
Get-LocalUser | Where-Object { $_.PasswordExpired -eq $true } | Select-Object Name,Enabled |
    Format-Table -AutoSize

3.03 Forzar cambio de contraseña a usuario
# 3.03 - Forzar cambio de contraseña en siguiente inicio
param($User="tempUser01")
$u = Get-LocalUser -Name $User -ErrorAction SilentlyContinue
if ($u) {
    Set-LocalUser -Name $User -PasswordNeverExpires $false
    Write-Host "Usuario $User marcado para cambio de contraseña en próximo inicio de sesión."
} else { Write-Host "Usuario no encontrado." }

3.04 Habilitar BitLocker en unidad (requiere permisos)
# 3.04 - Habilitar BitLocker en C: (requiere TPM/perm)
$SecurePwd = Read-Host "Introduce clave de recuperación" -AsSecureString
Enable-BitLocker -MountPoint "C:" -RecoveryPasswordProtector -Password $SecurePwd -EncryptionMethod XtsAes256 -UsedSpaceOnly
Write-Host "BitLocker iniciado en C: (comprueba estado)."

3.05 Buscar archivos con permisos inseguros (Everyone FullControl)
# 3.05 - Buscar archivos con permisos 'Everyone' FullControl en carpeta
$path = "C:\Compartido"
Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $acl = Get-Acl $_.FullName
    $acl.Access | Where-Object { $_.IdentityReference -like "*Everyone" -and $_.FileSystemRights -match "FullControl" } |
        ForEach-Object { [PSCustomObject]@{ File = $_.Path; Identity = $_.IdentityReference; Rights = $_.FileSystemRights } }
} | Format-Table -AutoSize

3.06 Habilitar auditoría para archivos en carpeta
# 3.06 - Habilitar auditoría de acceso en carpeta (requiere políticas)
$path = "C:\Compartido"
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone","Read","Success")
$acl = Get-Acl $path
$acl.AddAuditRule($rule)
Set-Acl -Path $path -AclObject $acl
Write-Host "Regla de auditoría añadida a $path"

3.07 Comprobar si Windows Defender está activo
# 3.07 - Estado de Windows Defender
Get-MpComputerStatus | Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,RealTimeProtectionEnabled |
    Format-List

3.08 Forzar escaneo rápido de Defender
# 3.08 - Escaneo rápido con Windows Defender
Start-MpScan -ScanType QuickScan
Write-Host "Escaneo rápido iniciado."

3.09 Revisar cuentas administrativas locales
# 3.09 - Miembros del grupo Administradores locales
Get-LocalGroupMember -Group "Administrators" | Select-Object Name,PrincipalSource | Format-Table -AutoSize

3.10 Listar políticas de bloqueo de cuenta (lockout)
# 3.10 - Obtener políticas locales de seguridad (lockout)
secedit /export /cfg C:\Windows\Temp\secpol.txt
Select-String -Path C:\Windows\Temp\secpol.txt -Pattern "Lockout" | Out-File C:\Logs\LockoutPolicy.txt
Write-Host "Políticas de bloqueo exportadas."

Active Directory

Nota: los scripts AD requieren módulo ActiveDirectory y permisos adecuados.

4.01 Buscar usuario en AD por sAMAccountName
# 4.01 - Buscar usuario AD
param($User="jsmith")
Import-Module ActiveDirectory
Get-ADUser -Identity $User -Properties DisplayName,SamAccountName,Enabled,LastLogonDate |
    Select-Object Name,SamAccountName,Enabled,LastLogonDate | Format-List

4.02 Crear usuario en AD (básico)
# 4.02 - Crear usuario AD (básico)
Import-Module ActiveDirectory
New-ADUser -Name "Temp AD User" -SamAccountName "temp.ad.user" -AccountPassword (ConvertTo-SecureString "P@ssTemp1" -AsPlainText -Force) -Enabled $true -Path "CN=Users,DC=example,DC=com"
Write-Host "Usuario AD creado (ajusta OU/Password según política)."

4.03 Resetear contraseña y forzar cambio
# 4.03 - Reset contraseña AD y forzar cambio
param($User="temp.ad.user")
Import-Module ActiveDirectory
Set-ADAccountPassword -Identity $User -Reset -NewPassword (ConvertTo-SecureString "N3wP@ssw0rd!" -AsPlainText -Force)
Set-ADUser -Identity $User -ChangePasswordAtLogon $true
Write-Host "Contraseña reset y forzar cambio en primer inicio."

4.04 Listar equipos inactivos >90 días
# 4.04 - Equipos inactivos >90 días
Import-Module ActiveDirectory
$lim = (Get-Date).AddDays(-90)
Get-ADComputer -Filter {LastLogonDate -lt $lim} -Properties LastLogonDate |
    Select-Object Name,LastLogonDate | Out-File C:\Logs\AD_InactiveComputers.txt

4.05 Añadir usuario a grupo AD
# 4.05 - Añadir usuario a grupo AD
param($User="jdoe",$Group="Domain Users")
Import-Module ActiveDirectory
Add-ADGroupMember -Identity $Group -Members $User
Write-Host "Usuario $User añadido a $Group"

4.06 Bloquear cuenta en AD
# 4.06 - Bloquear cuenta AD
param($User="temp.ad.user")
Import-Module ActiveDirectory
Search-ADAccount -UsersOnly -AccountDisabled -Identity $User -ErrorAction SilentlyContinue | Out-Null
Disable-ADAccount -Identity $User
Write-Host "Cuenta $User deshabilitada."

4.07 Exportar OU de usuarios a CSV
# 4.07 - Exportar usuarios de OU a CSV
Import-Module ActiveDirectory
Get-ADUser -Filter * -SearchBase "OU=Ventas,DC=example,DC=com" -Properties mail,Title |
    Select-Object SamAccountName,Name,mail,Title | Export-Csv C:\Logs\SalesUsers.csv -NoTypeInformation

4.08 Comprobar membresía de grupo recursiva
# 4.08 - Comprobar si usuario es miembro de un grupo (recursivo)
param($User="jdoe",$Group="Domain Admins")
Import-Module ActiveDirectory
$result = Get-ADUser -Identity $User -Properties MemberOf
if (Get-ADPrincipalGroupMembership $User | Where-Object { $_.Name -eq $Group }) { Write-Host "$User pertenece a $Group" } else { Write-Host "No pertenece." }

4.09 Buscar cuentas con contraseña nunca expira
# 4.09 - Cuentas AD con contraseña 'NeverExpires'
Import-Module ActiveDirectory
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires | Select-Object SamAccountName,Name |
    Out-File C:\Logs\AD_PwdNeverExpires.txt

4.10 Forzar sincronización de AD (si es DC)
# 4.10 - Forzar replicación de AD (ejecute en controlador de dominio)
Import-Module ActiveDirectory
Sync-ADObject -Object (Get-ADDomainController -Filter * | Select-Object -First 1).Name -ErrorAction SilentlyContinue
Write-Host "Intento de sincronización ejecutado (verifique eventos de replicación)."

Almacenamiento y backups
5.01 Crear snapshot VSS de volumen (básico)
# 5.01 - Crear snapshot VSS (ejecutar con privilegios)
$vssAdmin = "vssadmin"
& $vssAdmin Create Shadow /For=C:
Write-Host "Solicitud de snapshot enviada. Comprueba estado con vssadmin list shadows."

5.02 Copia simple de backup incremental por fecha
# 5.02 - Copia incremental por fecha
$src = "C:\Datos"
$dest = "D:\Backups\Datos_$(Get-Date -Format yyyyMMdd)"
New-Item -ItemType Directory -Path $dest -Force | Out-Null
Get-ChildItem $src -Recurse | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } |
    Copy-Item -Destination { Join-Path $dest ($_.FullName.Substring($src.Length).TrimStart('\')) } -Force -Container
Write-Host "Backup incremental realizado a $dest"

5.03 Comprobar integridad de backups (hash)
# 5.03 - Comprobar integridad por hash (MD5)
$files = Get-ChildItem "D:\Backups\Ultimo" -Recurse -File
$files | ForEach-Object { @{File=$_.FullName; MD5=(Get-FileHash $_.FullName -Algorithm MD5).Hash } } |
    ConvertTo-Csv -NoTypeInformation | Out-File C:\Logs\BackupHashes.csv
Write-Host "Hashes de backup calculados."

5.04 Montar unidad de red si disponible
# 5.04 - Montar unidad de red si está accesible
$netPath = "\\backupserver\share"
$drive = "Z:"
if (Test-Path $netPath) {
    New-PSDrive -Name $drive.TrimEnd(':') -PSProvider FileSystem -Root $netPath -Persist -ErrorAction SilentlyContinue
    Write-Host "Unidad $drive mapeada a $netPath"
} else { Write-Host "Ruta no accesible: $netPath" }

5.05 Eliminar backups antiguos >30 días
# 5.05 - Borrar backups antiguos
$folder = "D:\Backups"
Get-ChildItem $folder -Directory | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-30) } |
    Remove-Item -Recurse -Force -Confirm:$false
Write-Host "Backups antiguos eliminados."

5.06 Obtener uso de espacio por carpeta grande
# 5.06 - Top 10 carpetas por tamaño en C:\Datos
Get-ChildItem C:\Datos -Directory | ForEach-Object {
    [PSCustomObject]@{ Folder=$_.FullName; SizeGB = [math]::Round((Get-ChildItem $_.FullName -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum/1GB,2) }
} | Sort-Object SizeGB -Descending | Select-Object -First 10 | Format-Table -AutoSize

5.07 Crear archivo de comprobación (touch) para ver cambios
# 5.07 - Crear/Actualizar timestamp de archivo de comprobacion
$path = "D:\Backups\last_backup_stamp.txt"
New-Item -ItemType File -Path $path -Force | Out-Null
(Get-Item $path).LastWriteTime = Get-Date
Write-Host "Sello temporal actualizado en $path"

5.08 Exportar volúmenes y tamaños
# 5.08 - Exportar volúmenes y espacio a CSV
Get-Volume | Select-Object DriveLetter,FileSystemLabel,SizeRemaining,Size | Export-Csv C:\Logs\Volumes.csv -NoTypeInformation
Write-Host "Información de volúmenes exportada."

5.09 Compactar backup en ZIP (requiere 5.0+)
# 5.09 - Compactar carpeta de backup a ZIP
$src = "D:\Backups\Ultimo"
$zip = "D:\Backups\Ultimo.zip"
If (Test-Path $src) { Compress-Archive -Path $src\* -DestinationPath $zip -Force; Write-Host "ZIP creado: $zip" } else { Write-Host "Fuente no existe." }

5.10 Ver estado de disco SMART (simple)
# 5.10 - Consultar atributos SMART (Win32_DiskDrive)
Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue |
    ForEach-Object { @{ InstanceName = $_.InstanceName; PredictFailure = $_.PredictFailure } } |
    Format-Table -AutoSize

Logs y monitoreo
6.01 Monitorizar evento específico y alertar
# 6.01 - Buscar evento crítico en System y alertar
$events = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1; StartTime=(Get-Date).AddHours(-1)} -MaxEvents 50
if ($events) { $events | Select-Object TimeCreated,Id,Message | Out-File C:\Logs\CriticalSystemEvents.txt; Write-Host "Eventos críticos encontrados." } else { Write-Host "Sin eventos críticos en la última hora." }

6.02 Generar report diario de CPU/Disk/RAM
# 6.02 - Report diario simple
$cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
$mem = Get-WmiObject Win32_OperatingSystem
$disk = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -eq 'C' }
"{0} | CPU:{1}% | MemFree:{2}MB | C_Free:{3}GB" -f (Get-Date), [math]::Round($cpu,2), [math]::Round($mem.FreePhysicalMemory/1KB,2), [math]::Round($disk.Free/1GB,2) |
    Out-File C:\Logs\DailyReport.txt -Append

6.03 Leer y filtrar eventos de aplicación
# 6.03 - Filtrar eventos de Application con ID específico
$ids = @(1000,1001)
Get-WinEvent -FilterHashtable @{LogName='Application'; Id=$ids; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 200 |
    Select-Object TimeCreated,Id,ProviderName,Message | Format-Table -AutoSize

6.04 Monitorizar archivos de log y mostrar nuevas líneas
# 6.04 - Mostrar nuevas líneas de log (tail -f)
$path = "C:\Logs\Application.log"
Get-Content -Path $path -Wait -Tail 10

6.05 Enviar resumen por correo (usando Send-MailMessage)
# 6.05 - Enviar resumen por correo (configura SMTP)
$body = Get-Content C:\Logs\DailyReport.txt | Out-String
Send-MailMessage -From admin@example.com -To ops@example.com -Subject "Resumen Diario" -Body $body -SmtpServer "smtp.example.com"
Write-Host "Correo enviado (si SMTP configurado)."

6.06 Generar alertas si CPU > 90%
# 6.06 - Alerta simple uso CPU
$cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
if ($cpu -gt 90) { Write-Host "ALERTA: CPU > 90% ($([math]::Round($cpu,2))%)" -ForegroundColor Red }
else { Write-Host "CPU OK: $([math]::Round($cpu,2))%" }

6.07 Guardar logs de IIS (ejemplo de lectura)
# 6.07 - Mostrar últimos logs de IIS (ruta por defecto)
$logPath = "C:\inetpub\logs\LogFiles\W3SVC1"
Get-ChildItem $logPath -File | Sort-Object LastWriteTime -Descending | Select-Object -First 3 | ForEach-Object { Get-Content $_.FullName -Tail 20 }

6.08 Extraer eventos de seguridad por usuario
# 6.08 - Eventos de seguridad por usuario en 7 días
param($User="jdoe")
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-7)} |
    Where-Object { $_.Message -match $User } | Select-Object TimeCreated,Id,Message | Out-File C:\Logs\Security_$User.txt

6.09 Crear dashboard CSV de métricas
# 6.09 - Exportar métricas a CSV
$cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
$memFree = (Get-WmiObject Win32_OperatingSystem).FreePhysicalMemory
[PSCustomObject]@{ Time=Get-Date; CPU=[math]::Round($cpu,2); MemFreeMB=[math]::Round($memFree/1KB,2) } |
    Export-Csv C:\Logs\Metrica_$(Get-Date -Format yyyyMMdd).csv -NoTypeInformation -Append

6.10 Buscar errores críticos en Windows Update
# 6.10 - Buscar errores en log de Windows Update
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WindowsUpdateClient'; Level=2; StartTime=(Get-Date).AddDays(-7)} |
    Select-Object TimeCreated,Id,Message | Out-File C:\Logs\WU_Errors.txt

Automatización de tareas programadas
7.01 Crear tarea que ejecute script con credenciales (seguro)
# 7.01 - Crear tarea programada con credenciales
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -File `""C:\Scripts\Backup.ps1`""
$Trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName "BackupDiario" -Action $Action -Trigger $Trigger -RunLevel Highest
Write-Host "Tarea BackupDiario creada."

7.02 Deshabilitar tarea por nombre
# 7.02 - Deshabilitar tarea programada
$task = "ReinicioServer"
If (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) { Disable-ScheduledTask -TaskName $task; Write-Host "Tarea $task deshabilitada." } else { Write-Host "Tarea no encontrada." }

7.03 Exportar tareas programadas a XML
# 7.03 - Exportar tarea a XML
$task = "BackupDiario"
$exp = schtasks /query /xml /tn $task
$exp | Out-File C:\Logs\$task.xml
Write-Host "Exportado $task a XML."

7.04 Ejecutar tarea manualmente ahora
# 7.04 - Ejecutar tarea ahora
$task = "BackupDiario"
Start-ScheduledTask -TaskName $task
Write-Host "Tarea $task iniciada manualmente."

7.05 Listar tareas habilitadas
# 7.05 - Listar tareas habilitadas
Get-ScheduledTask | Where-Object { $_.State -eq "Ready" -or $_.State -eq "Running" } | Select-Object TaskName,State | Format-Table -AutoSize

7.06 Crear trigger semanal
# 7.06 - Crear tarea semanal
$Action = New-ScheduledTaskAction -Execute "notepad.exe"
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 09:00AM
Register-ScheduledTask -TaskName "AbrirNotepad_Lunes" -Action $Action -Trigger $Trigger
Write-Host "Tarea semanal creada."

7.07 Borrar tarea programada
# 7.07 - Borrar tarea
$task = "AbrirNotepad_Lunes"
Unregister-ScheduledTask -TaskName $task -Confirm:$false
Write-Host "Tarea $task eliminada."

7.08 Obtener historial de ejecución de una tarea
# 7.08 - Historial de ejecución de tarea
$task = "BackupDiario"
Get-ScheduledTask -TaskName $task | Get-ScheduledTaskInfo | Select-Object LastRunTime,LastTaskResult,NextRunTime | Format-List

7.09 Copiar tarea a otro servidor (export/import)
# 7.09 - Exportar e importar tarea a otro servidor (localmente)
$task = "BackupDiario"
schtasks /query /tn $task /xml > C:\Logs\$task.xml
# En otro servidor usar: schtasks /create /tn $task /xml C:\Logs\$task.xml
Write-Host "Tarea exportada a C:\Logs\$task.xml"

7.10 Ejecutar script cuando detecte archivo nuevo en carpeta
# 7.10 - Watcher simple para ejecutar acción en archivo nuevo
$folder = "C:\Incoming"
$fsw = New-Object IO.FileSystemWatcher $folder -Property @{IncludeSubdirectories=$false; NotifyFilter = [IO.NotifyFilters]'FileName,LastWrite'}
$action = { param($s,$e) Write-Host "Archivo nuevo: $($e.Name)"; & "C:\Scripts\Procesar.ps1" $e.FullPath }
Register-ObjectEvent $fsw Created -Action $action | Out-Null
Write-Host "Watcher activo en $folder"

IIS y web
8.01 Listar sitios IIS y estado
# 8.01 - Listar sitios IIS
Import-Module WebAdministration
Get-ChildItem IIS:\Sites | Select-Object Name,State,Bindings | Format-Table -AutoSize

8.02 Reiniciar un sitio IIS
# 8.02 - Reiniciar sitio IIS
param($site="Default Web Site")
Import-Module WebAdministration
Stop-WebSite -Name $site
Start-Site -Name $site
Write-Host "Sitio $site reiniciado."

8.03 Habilitar/deshabilitar pool de aplicaciones
# 8.03 - Controlar AppPool
param($appPool="DefaultAppPool",$Enable=$true)
Import-Module WebAdministration
if ($Enable) { Start-WebAppPool $appPool } else { Stop-WebAppPool $appPool }
Write-Host "AppPool $appPool - Enable=$Enable"

8.04 Exportar bindings de sitio
# 8.04 - Exportar bindings de un sitio IIS
$site = "Default Web Site"
Import-Module WebAdministration
Get-WebBinding -Name $site | Select-Object Protocol,BindingInformation | Export-Csv C:\Logs\IIS_Bindings_$($site.Replace(' ','_')).csv -NoTypeInformation
Write-Host "Bindings exportados."

8.05 Rotación de logs de IIS moviéndolos por fecha
# 8.05 - Mover logs antiguos de IIS
$logDir = "C:\inetpub\logs\LogFiles\W3SVC1"
$cutoff = (Get-Date).AddDays(-7)
Get-ChildItem $logDir -File | Where-Object { $_.LastWriteTime -lt $cutoff } |
    Move-Item -Destination "D:\IISLogs\Archive"
Write-Host "Logs antiguos archivados."

8.06 Comprobar disponibilidad HTTP de sitio local
# 8.06 - Probar HTTP local
param($Url="http://localhost")
$res = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue
if ($res.StatusCode -eq 200) { Write-Host "OK: $Url responde 200" } else { Write-Host "Respuesta inesperada o no accesible." }

8.07 Crear archivo web.config básico en sitio
# 8.07 - Crear web.config si no existe
$sitePath = "C:\inetpub\wwwroot"
$config = Join-Path $sitePath "web.config"
if (-not (Test-Path $config)) {
    @"<configuration><system.webServer><handlers></handlers></system.webServer></configuration>"@ | Out-File $config -Encoding UTF8
    Write-Host "web.config creado en $sitePath"
} else { Write-Host "web.config ya existe." }

8.08 Obtener certificados vinculados en bindings HTTPS
# 8.08 - Mostrar certs en bindings HTTPS
Import-Module WebAdministration
Get-WebBinding | Where-Object { $_.protocol -eq "https" } | ForEach-Object {
    $_ | Select-Object bindingInformation,sslFlags
} | Format-Table -AutoSize

8.09 Forzar recarga de apppool tras cambios
# 8.09 - Recycle de AppPool si archivos cambiaron
$appPool="DefaultAppPool"
Stop-WebAppPool $appPool
Start-WebAppPool $appPool
Write-Host "AppPool $appPool reciclado tras cambios."

8.10 Extraer últimas 100 líneas de log de sitio
# 8.10 - Leer últimas 100 líneas del log más reciente
$log = Get-ChildItem "C:\inetpub\logs\LogFiles\W3SVC1" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Get-Content $log.FullName -Tail 100

PowerShell remoting y clusters
9.01 Habilitar WinRM y permitir remoting
# 9.01 - Habilitar WinRM
Enable-PSRemoting -Force
Set-Item wsman:\localhost\client\trustedhosts -Value "*" -Force
Write-Host "PSRemoting habilitado (ajusta TrustedHosts según política)."

9.02 Ejecutar comando remoto en lista de servidores
# 9.02 - Ejecutar comando remoto
$servers = @("srv01","srv02")
Invoke-Command -ComputerName $servers -ScriptBlock { Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name,CPU } -Credential (Get-Credential)

9.03 Copiar archivo a varios servidores con Copy-Item -ToSession
# 9.03 - Copiar archivo a servidores remotos
$servers = @("srv01","srv02")
$cred = Get-Credential
foreach ($s in $servers) {
    $sess = New-PSSession -ComputerName $s -Credential $cred
    Copy-Item -Path "C:\Scripts\Tool.ps1" -Destination "C:\Scripts\" -ToSession $sess
    Remove-PSSession $sess
    Write-Host "Copiado a $s"
}

9.04 Comprobar estado de clúster (failover cluster)
# 9.04 - Estado básico de cluster
Import-Module FailoverClusters
Get-Cluster | Get-ClusterNode | Select-Object Name,State | Format-Table -AutoSize

9.05 Reiniciar grupo en cluster (simple)
# 9.05 - Reiniciar recurso de cluster
Import-Module FailoverClusters
$group = "Cluster Group"
Get-ClusterGroup -Name $group | Start-ClusterGroup
Write-Host "Grupo $group arrancado."

9.06 Ejecutar script en paralelo con PSSessions
# 9.06 - Ejecutar en paralelo
$servers = @("srv01","srv02","srv03")
$sess = New-PSSession -ComputerName $servers
Invoke-Command -Session $sess -ScriptBlock { Get-Service | Where-Object {$_.Status -ne "Running"} }
Remove-PSSession $sess

9.07 Crear sesión persistente y abrir shell interactivo
# 9.07 - Sesión persistente
$s = New-PSSession -ComputerName "srv01"
Enter-PSSession -Session $s
# Para salir: Exit-PSSession y Remove-PSSession $s

9.08 Validar credenciales remotas
# 9.08 - Validar credenciales en remoto
$cred = Get-Credential
Test-WSMan -ComputerName "srv01" -Credential $cred -ErrorAction SilentlyContinue
if ($?) { Write-Host "Conexión WSMan OK" } else { Write-Host "Problema de conexión o credenciales." }

9.09 Ejecutar actualizaciones pendientes en remoto (básico)
# 9.09 - Forzar chequeo de Windows Update remoto (require PSWindowsUpdate módulo)
Invoke-Command -ComputerName "srv01" -ScriptBlock { Install-Module PSWindowsUpdate -Force; Get-WindowsUpdate -Install -AcceptAll -AutoReboot } -Credential (Get-Credential)

9.10 Recuperar eventos del sistema remoto
# 9.10 - Leer eventos del sistema remoto
Invoke-Command -ComputerName "srv01" -ScriptBlock { Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddHours(-6)} -MaxEvents 100 } -Credential (Get-Credential)

Herramientas misceláneas (limpieza, reportes, utilidades)
10.01 Limpiar temporales de usuarios
# 10.01 - Limpiar %TEMP% de todos los perfiles
Get-ChildItem C:\Users -Directory | ForEach-Object {
    $t = Join-Path $_.FullName "AppData\Local\Temp"
    if (Test-Path $t) { Get-ChildItem $t -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
}
Write-Host "Temporales de perfiles limpiados."

10.02 Comprimir logs antiguos para ahorrar espacio
# 10.02 - Comprimir archivos de log antiguos
$path = "C:\Logs"
Get-ChildItem $path -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-14) } |
    ForEach-Object { Compress-Archive -Path $_.FullName -DestinationPath ($_.FullName + ".zip"); Remove-Item $_.FullName -Force }
Write-Host "Logs antiguos comprimidos."

10.03 Generar reporte de software instalado
# 10.03 - Lista de software instalado (HKLM Uninstall)
$keys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
$apps = foreach ($k in $keys) { Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty $_.PSPath } }
$apps | Select-Object DisplayName,DisplayVersion,Publisher | Export-Csv C:\Logs\InstalledSoftware.csv -NoTypeInformation

10.04 Buscar archivos duplicados por hash (en carpeta)
# 10.04 - Duplicados por hash
$files = Get-ChildItem "C:\Datos" -Recurse -File
$hashes = $files | Group-Object { (Get-FileHash $_.FullName -Algorithm SHA256).Hash } | Where-Object { $_.Count -gt 1 }
$hashes | ForEach-Object { $_.Group | Select-Object FullName } | Out-File C:\Logs\Duplicates.txt
Write-Host "Búsqueda de duplicados completada."

10.05 Crear atajo en escritorio para administración
# 10.05 - Crear .lnk en escritorio
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:Public\Desktop\AdminTools.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$Shortcut.Arguments = "-NoExit -Command `"cd C:\Scripts`""
$Shortcut.Save()
Write-Host "Acceso directo creado en escritorio público."

10.06 Reportar versiones de .NET instaladas
# 10.06 - Obtener versiones .NET instaladas (simple)
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" -Recurse |
    Get-ItemProperty -Name Version -ErrorAction SilentlyContinue | Where-Object { $_.Version } |
    Select-Object PSChildName,Version | Sort-Object Version -Descending | Format-Table -AutoSize

10.07 Limpiar papelera de reciclaje para todos los usuarios (admin)
# 10.07 - Vaciar papelera de todos los usuarios (requiere privilegios)
$users = Get-ChildItem C:\Users -Directory
foreach ($u in $users) {
    $recycle = Join-Path $u.FullName "AppData\Local\Microsoft\Windows\Recycle.Bin"
    if (Test-Path $recycle) { Remove-Item "$recycle\*" -Recurse -Force -ErrorAction SilentlyContinue }
}
Write-Host "Papelera vaciada para usuarios accesibles."

10.08 Convertir CSV a HTML para reporte rápido
# 10.08 - CSV -> HTML
$csv = Import-Csv C:\Logs\InstalledSoftware.csv
$csv | ConvertTo-Html -Title "Software Instalado" | Out-File C:\Logs\InstalledSoftware.html
Write-Host "Reporte HTML generado."

10.09 Mostrar hora y sincronizar contra NTP
# 10.09 - Sincronizar hora con servidor NTP
w32tm /config /manualpeerlist:"time.windows.com" /syncfromflags:manual /update
w32tm /resync /nowait
Write-Host "Sincronización horaria solicitada."

10.10 Comprobar integridad de archivos del sistema (SFC)
# 10.10 - Ejecutar SFC
sfc /scannow
Write-Host "sfc /scannow ejecutado. Revisa resultados en la consola."

BLOQUE 1 — COPIAS DE SEGURIDAD
1) Copia de seguridad simple con ZIP
# Función que realiza una copia comprimida (ZIP) de una ruta origen a una ruta destino.
function Backup-Zip {
    # Solicitamos al usuario la ruta de origen que desea respaldar.
    $source = Read-Host "Ruta de origen"
    # Solicitamos al usuario la carpeta donde guardar la copia comprimida.
    $dest = Read-Host "Ruta destino"
    # Obtenemos la fecha actual formateada para incluirla en el nombre del fichero.
    $fecha = Get-Date -Format "yyyyMMdd_HHmm"
    # Construimos la ruta completa del archivo ZIP que se va a crear.
    $zip = "$dest\Backup_$fecha.zip"
    # Comprimimos la ruta origen en el ZIP destino; -Force sobrescribe si ya existe.
    Compress-Archive -Path $source -DestinationPath $zip -Force
    # Informamos al usuario de que se ha creado la copia y su ubicación.
    Write-Host "Copia creada en $zip"
}
# Llamamos a la función para ejecutar el procedimiento interactivo.
Backup-Zip

2) Copia incremental según fecha
# Función que copia solo archivos modificados en los últimos N días.
function Backup-Incremental {
    # Pedimos la carpeta origen al usuario.
    $source = Read-Host "Carpeta origen"
    # Pedimos la carpeta destino donde copiar los archivos.
    $dest = Read-Host "Carpeta destino"
    # Pedimos cuántos días hacia atrás considerar para la incrementalidad.
    $days = Read-Host "Días hacia atrás"
    # Calculamos la fecha límite: archivos con LastWriteTime mayor a esta serán copiados.
    $fecha = (Get-Date).AddDays(-[int]$days)
    # Enumeramos archivos recursivamente y filtramos por fecha de modificación.
    Get-ChildItem $source -Recurse | Where-Object {$_.LastWriteTime -gt $fecha} |
    # Copiamos cada archivo filtrado a la ruta destino, forzando la sobrescritura.
    Copy-Item -Destination $dest -Force
    # Indicamos al operador que la tarea terminó.
    Write-Host "Archivos modificados en $days días copiados."
}
# Ejecutamos la función para iniciar la interacción.
Backup-Incremental

3) Copia de perfiles de usuario con robocopy
# Función que realiza copia espejo (robocopy /MIR) de cada perfil de C:\Users (excepto Public).
function Backup-Users {
    # Ruta donde se guardarán los respaldos.
    $backupPath = Read-Host "Carpeta destino para respaldos"
    # Listamos directorios de perfiles, excluyendo 'Public'.
    $users = Get-ChildItem "C:\Users" -Directory | Where-Object {$_.Name -ne "Public"}
    # Iteramos por cada perfil encontrado.
    foreach ($u in $users) {
        # Construimos la ruta destino específica para ese usuario.
        $dest = "$backupPath\$($u.Name)"
        # Ejecutamos robocopy con opciones robustas (MIR = espejo, Z = modo reiniciable).
        robocopy $u.FullName $dest /MIR /Z /R:2 /W:2 | Out-Null
        # Informamos que el perfil concreto fue respaldado correctamente.
        Write-Host "Perfil de $($u.Name) respaldado."
    }
}
# Lanzamos la función.
Backup-Users

4) Exportar el registro del sistema
# Función que exporta las ramas HKLM y HKCU del registro a archivos .reg.
function Backup-Registry {
    # Solicitamos al usuario la carpeta donde guardar los archivos .reg.
    $dest = Read-Host "Carpeta donde guardar los .reg"
    # Obtenemos la fecha para nombrar los ficheros de forma única.
    $fecha = Get-Date -Format "yyyyMMdd"
    # Exportamos HKLM a un archivo .reg con reg.exe (herramienta nativa).
    reg export HKLM "$dest\HKLM_$fecha.reg"
    # Exportamos HKCU a otro archivo .reg.
    reg export HKCU "$dest\HKCU_$fecha.reg"
    # Mensaje final al usuario.
    Write-Host "Registro exportado correctamente."
}
# Ejecutamos la función para que el usuario interactúe.
Backup-Registry

5) Sincronizar carpetas con Robocopy
# Función que sincroniza (mirror) dos carpetas usando robocopy y genera un log.
function Sync-Folders {
    # Solicitamos la carpeta de origen.
    $src = Read-Host "Ruta origen"
    # Solicitamos la carpeta destino.
    $dst = Read-Host "Ruta destino"
    # Ejecutamos robocopy en modo espejo y guardamos un log en la carpeta destino.
    robocopy $src $dst /MIR /Z /LOG:"$dst\sync.log"
    # Informamos al usuario de la finalización.
    Write-Host "Sincronización completada entre $src y $dst"
}
# Invocamos la función.
Sync-Folders

6) Copia de seguridad del estado del sistema (wbadmin)
# Función que solicita una ruta y lanza wbadmin para hacer backup del System State.
function Backup-SystemState {
    # Pedimos dónde almacenar el backup del estado del sistema.
    $path = Read-Host "Ruta para guardar el backup del sistema"
    # Ejecutamos wbadmin (herramienta Windows) en modo silencioso (-quiet).
    cmd /c "wbadmin start systemstatebackup -backuptarget:$path -quiet"
    # Indicamos al operador que la solicitud fue lanzada.
    Write-Host "Copia del estado del sistema creada."
}
# Llamada a la función.
Backup-SystemState

7) Validar integridad de backups con hash
# Función que calcula y muestra hashes (SHA256) de los archivos en una carpeta.
function Verify-Hash {
    # Solicitamos la ruta a analizar.
    $path = Read-Host "Carpeta para analizar"
    # Listamos todos los archivos recursivamente en la ruta indicada.
    $files = Get-ChildItem $path -Recurse -File
    # Para cada archivo calculamos su hash y mostramos una parte legible.
    foreach ($f in $files) {
        $hash = Get-FileHash $f.FullName
        # Mostramos el nombre de archivo y los primeros 16 caracteres del hash.
        Write-Host "$($f.Name): $($hash.Hash.Substring(0,16))"
    }
}
# Ejecutamos la función para interacción.
Verify-Hash

8) Eliminar backups antiguos automáticamente
# Función que borra archivos/carpetas más antiguos que N días en una ruta.
function Cleanup-OldBackups {
    # Solicitamos la carpeta base donde están los backups.
    $path = Read-Host "Carpeta de backups"
    # Solicitamos el umbral en días para eliminar.
    $days = Read-Host "Eliminar backups con más de (días)"
    # Buscamos items cuya LastWriteTime es anterior a la fecha calculada y los eliminamos.
    Get-ChildItem $path -Recurse | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-[int]$days)} |
    Remove-Item -Recurse -Force
    # Aviso de finalización al usuario.
    Write-Host "Backups antiguos eliminados."
}
# Ejecutamos la limpieza interacción.
Cleanup-OldBackups

9) Reporte de tamaño total de backups
# Función que calcula el tamaño total (GB) de una carpeta de backups.
function Report-BackupSize {
    # Solicitamos la ruta de la carpeta a analizar.
    $path = Read-Host "Ruta de la carpeta de backups"
    # Medimos la suma de los tamaños de los archivos y convertimos a GB.
    $total = (Get-ChildItem $path -Recurse -File | Measure-Object -Property Length -Sum).Sum /1GB
    # Mostramos el resultado redondeado a 2 decimales.
    Write-Host "Tamaño total: $([math]::Round($total,2)) GB"
}
# Lanzamos la función.
Report-BackupSize

10) Backup completo del disco con robocopy
# Función que realiza una copia tipo "imagen" del contenido de una unidad a destino.
function Backup-Disk {
    # Pedimos al usuario la letra de la unidad (sin dos puntos).
    $disk = Read-Host "Letra de unidad (sin dos puntos)"
    # Pedimos la ruta destino donde se almacenará la copia.
    $dest = Read-Host "Ruta destino"
    # Ejecutamos robocopy desde la raíz de la unidad seleccionada al destino, excluyendo archivos ocultos (-XA:H).
    robocopy "$($disk):\" $dest /MIR /Z /XA:H /LOG:"$dest\disk_backup.log"
    # Indicamos al usuario que el proceso terminó.
    Write-Host "Backup del disco $disk completado."
}
# Ejecutamos la función.
Backup-Disk

BLOQUE 2 — USUARIOS
11) Crear usuario local interactivo
# Función que crea un usuario local pidiendo nombre y contraseña por consola.
function Create-User {
    # Pedimos el nombre de usuario que queremos crear.
    $user = Read-Host "Nombre del usuario"
    # Pedimos la contraseña en texto plano (se convertirá a SecureString).
    $pass = Read-Host "Contraseña"
    # Convertimos la contraseña a SecureString porque New-LocalUser lo requiere.
    $secure = ConvertTo-SecureString $pass -AsPlainText -Force
    # Creamos el usuario local con el nombre y la contraseña proporcionados.
    New-LocalUser -Name $user -Password $secure
    # Mensaje confirmando la creación.
    Write-Host "Usuario $user creado."
}
# Ejecutamos la función para crear el usuario.
Create-User

12) Eliminar usuario local interactivo
# Función que elimina un usuario local solicitando su nombre.
function Remove-User {
    # Solicitamos el nombre del usuario a eliminar.
    $user = Read-Host "Nombre del usuario a eliminar"
    # Intentamos eliminar el usuario; SilentlyContinue evita errores si no existe.
    Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
    # Informamos al operador que la operación se intentó.
    Write-Host "Usuario $user eliminado."
}
# Llamada para iniciar la operación.
Remove-User

13) Cambiar contraseña de usuario
# Función que cambia la contraseña de un usuario local.
function Change-Password {
    # Preguntamos el nombre del usuario cuya contraseña queremos cambiar.
    $user = Read-Host "Usuario"
    # Pedimos la nueva contraseña en texto plano.
    $pass = Read-Host "Nueva contraseña"
    # Convertimos la contraseña a SecureString para la API de Windows.
    $secure = ConvertTo-SecureString $pass -AsPlainText -Force
    # Aplicamos la nueva contraseña al usuario especificado.
    Set-LocalUser -Name $user -Password $secure
    # Confirmamos la operación.
    Write-Host "Contraseña actualizada."
}
# Ejecutamos la función.
Change-Password

14) Agregar usuario a un grupo local
# Función para incluir un usuario en un grupo local.
function Add-ToGroup {
    # Solicitamos el nombre del usuario.
    $user = Read-Host "Usuario"
    # Solicitamos el nombre del grupo local.
    $group = Read-Host "Grupo"
    # Añadimos el miembro al grupo local especificado.
    Add-LocalGroupMember -Group $group -Member $user
    # Mensaje de confirmación.
    Write-Host "$user agregado al grupo $group."
}
# Ejecutamos la función que pide los datos e interactúa.
Add-ToGroup

15) Deshabilitar usuario local
# Función que deshabilita (inactiva) una cuenta local.
function Disable-User {
    # Pedimos el nombre de la cuenta a deshabilitar.
    $user = Read-Host "Usuario a deshabilitar"
    # Deshabilitamos la cuenta usando el cmdlet correspondiente.
    Disable-LocalUser -Name $user
    # Confirmamos al operador que la cuenta fue deshabilitada.
    Write-Host "Usuario $user deshabilitado."
}
# Llamada a la función.
Disable-User

16) Listar usuarios locales activos (sin Read-Host)
# Función que muestra los usuarios locales habilitados y su último logon conocido.
function List-Users {
    # Obtenemos todos los usuarios locales y filtramos por Enabled = $true.
    Get-LocalUser | Where-Object {$_.Enabled -eq $true} | Select Name, LastLogon
}
# Ejecutamos la función para listar usuarios en pantalla.
List-Users

17) Crear varios usuarios desde CSV
# Función que crea usuarios en lote leyendo un CSV con columnas User y Password.
function Create-MultiUser {
    # Pedimos la ruta del archivo CSV que contiene los usuarios a crear.
    $path = Read-Host "Ruta del CSV (User,Password)"
    # Importamos las filas del CSV y por cada entrada creamos un usuario local.
    Import-Csv $path | ForEach-Object {
        # Convertimos la contraseña leída a SecureString.
        $p = ConvertTo-SecureString $_.Password -AsPlainText -Force
        # Creamos el usuario con nombre y contraseña desde el CSV.
        New-LocalUser -Name $_.User -Password $p
    }
    # Mensaje final indicando que la operación terminó.
    Write-Host "Usuarios creados desde $path"
}
# Llamada interactiva para ejecutar el proceso.
Create-MultiUser

18) Exportar lista de usuarios a CSV
# Función que exporta la lista de usuarios locales con algunos atributos a un CSV.
function Export-Users {
    # Pedimos la ruta donde se guardará el CSV.
    $path = Read-Host "Ruta para guardar CSV"
    # Seleccionamos Name, Enabled y LastLogon de cada usuario y lo exportamos.
    Get-LocalUser | Select Name, Enabled, LastLogon | Export-Csv $path -NoTypeInformation
    # Confirmación al operador.
    Write-Host "Exportado a $path"
}
# Ejecutamos la exportación.
Export-Users

19) Cambiar el nombre completo de un usuario
# Función para actualizar la propiedad FullName de una cuenta local.
function Rename-UserFullName {
    # Solicitamos el identificador del usuario.
    $user = Read-Host "Usuario"
    # Solicitamos el nuevo valor para el campo Nombre completo.
    $name = Read-Host "Nuevo nombre completo"
    # Aplicamos el cambio mediante Set-LocalUser.
    Set-LocalUser -Name $user -FullName $name
    # Mensaje final de confirmación.
    Write-Host "Nombre actualizado."
}
# Llamada a la función para interactuar.
Rename-UserFullName

20) Forzar cambio de contraseña al próximo inicio
# Función que marca una cuenta para que exija cambio de contraseña en el próximo logon.
function Force-ChangePassword {
    # Pedimos el usuario objetivo.
    $user = Read-Host "Usuario"
    # Ajustamos la política del usuario para que la contraseña no sea 'never expires'.
    Set-LocalUser -Name $user -PasswordNeverExpires $false
    # Mensaje indicando que el cambio será requerido.
    Write-Host "Cambio de contraseña requerido para $user."
}
# Ejecutamos la función para efectuar la modificación.
Force-ChangePassword

BLOQUE 3 — MATEMÁTICAS (interactivas y didácticas)
21) Factorial con recursión (interactivo)
# Función que calcula el factorial de un número leído por consola usando recursión.
function Get-Factorial {
    # Solicitamos el número al usuario y forzamos tipo entero.
    $n = [int](Read-Host "Número")
    # Definimos la función recursiva interna Fact.
    function Fact($x){if($x -le 1){1}else{$x * (Fact($x-1))}}
    # Llamamos a la función recursiva y mostramos el resultado.
    Write-Host "Factorial de $n = $(Fact $n)"
}
# Ejecutamos la función para pedir datos e imprimir el factorial.
Get-Factorial

22) Media y desviación estándar (desde entrada)
# Función que calcula media y desviación de una lista de números introducida por el usuario.
function Stats {
    # Pedimos al usuario una línea con números separados por coma.
    $nums = (Read-Host "Introduce números separados por coma").Split(",") | % {[double]$_}
    # Calculamos la media usando Measure-Object.
    $avg = ($nums | Measure-Object -Average).Average
    # Calculamos la desviación estándar mediante la raíz cuadrada de la varianza.
    $std = [math]::Sqrt(($nums | % {($_ - $avg) ** 2} | Measure-Object -Average).Average)
    # Mostramos los resultados redondeando la desviación para legibilidad.
    Write-Host "Media: $avg | Desviación: $([math]::Round($std,2))"
}
# Llamada para ejecutar.
Stats

23) Resolver ecuación cuadrática (pedir coeficientes)
# Función que resuelve ax^2 + bx + c = 0 pidiendo a, b y c al usuario.
function Quadratic {
    # Solicitamos el coeficiente a, b y c como dobles.
    $a = [double](Read-Host "a")
    $b = [double](Read-Host "b")
    $c = [double](Read-Host "c")
    # Calculamos el discriminante y su raíz cuadrada (puede lanzar excepción si negativo).
    $d = [math]::Sqrt(($b*$b)-(4*$a*$c))
    # Calculamos las dos soluciones usando la fórmula general.
    $x1 = (-$b + $d) / (2*$a)
    $x2 = (-$b - $d) / (2*$a)
    # Mostramos las soluciones en pantalla.
    Write-Host "x1=$x1  x2=$x2"
}
# Ejecutamos la función para interactuar.
Quadratic

24) Fibonacci (N términos)
# Función que genera la secuencia de Fibonacci hasta N términos solicitados.
function Fibonacci {
    # Pedimos el número de términos a generar.
    $n = [int](Read-Host "Cantidad de términos")
    # Inicializamos los primeros valores de la secuencia.
    $a=0;$b=1
    # Iteramos desde 1 hasta N y mostramos cada término.
    for($i=1;$i -le $n;$i++){
        Write-Host $a
        # Actualizamos los valores para el siguiente término.
        $tmp=$a+$b;$a=$b;$b=$tmp
    }
}
# Llamada que ejecuta la generación según entrada del usuario.
Fibonacci

25) Mostrar números primos hasta N
# Función que lista todos los números primos hasta un límite N indicado por el usuario.
function Prime-Upto {
    # Solicitamos el límite superior al operador.
    $n = [int](Read-Host "Límite superior")
    # Iteramos desde 2 hasta N para evaluar primalidad.
    for($i=2;$i -le $n;$i++){
        $isPrime=$true
        # Probamos divisores hasta la raíz cuadrada de i para eficiencia.
        for($j=2;$j -le [math]::Sqrt($i);$j++){if($i%$j -eq 0){$isPrime=$false;break}}
        # Si no se encontró divisor, se trata de un primo; lo mostramos.
        if($isPrime){Write-Host $i}
    }
}
# Ejecutamos la función para obtener la lista de primos.
Prime-Upto

26) Interés compuesto (con parámetros por consola)
# Función que calcula el valor futuro de un capital con interés compuesto.
function Interest {
    # Pedimos al usuario el capital inicial (double).
    $c = [double](Read-Host "Capital")
    # Pedimos la tasa anual en porcentaje.
    $t = [double](Read-Host "Tasa (%)")
    # Pedimos el número de años.
    $y = [int](Read-Host "Años")
    # Calculamos el monto final usando la fórmula del interés compuesto.
    $monto = $c * [math]::Pow((1+$t/100),$y)
    # Mostramos el resultado redondeado a 2 decimales.
    Write-Host "Monto final: $([math]::Round($monto,2))"
}
# Ejecutamos la función para pedir datos e imprimir el resultado.
Interest

27) Suma de la serie 1..N
# Función simple que calcula la suma de los enteros de 1 a N introducido por el usuario.
function Sum-Series {
    # Solicitamos N al usuario.
    $n = [int](Read-Host "Número N")
    # Inicializamos acumulador e iteramos sumando cada entero.
    $sum = 0;for($i=1;$i -le $n;$i++){$sum += $i}
    # Mostramos el total acumulado.
    Write-Host "Suma = $sum"
}
# Llamada para ejecutar la sumatoria.
Sum-Series

28) Conversor de grados a radianes
# Función que convierte grados a radianes pidiendo el valor por consola.
function DegToRad {
    # Leemos el valor de grados desde la entrada del usuario.
    $g = [double](Read-Host "Grados")
    # Fórmula: radianes = grados * PI / 180.
    $r = $g * [math]::PI / 180
    # Mostramos el resultado al usuario.
    Write-Host "$g° = $r rad"
}
# Ejecutamos la función para realizar la conversión interactiva.
DegToRad

29) Promedio ponderado (valores y pesos por consola)
# Función que calcula un promedio ponderado a partir de listas de valores y pesos.
function Weighted-Average {
    # Leemos los valores separados por coma y los convertimos a doubles.
    $values = (Read-Host "Valores separados por coma").Split(",") | % {[double]$_}
    # Leemos los pesos correspondientes y los convertimos a doubles.
    $weights = (Read-Host "Pesos separados por coma").Split(",") | % {[double]$_}
    # Calculamos la suma ponderada multiplicando cada valor por su peso.
    $sum=0;for($i=0;$i -lt $values.Count;$i++){$sum += $values[$i]*$weights[$i]}
    # Dividimos entre la suma de pesos para obtener el promedio ponderado.
    $res=$sum/($weights | Measure-Object -Sum).Sum
    # Mostramos el promedio redondeado.
    Write-Host "Promedio ponderado = $([math]::Round($res,2))"
}
# Ejecutamos la función para que el usuario introduzca valores y pesos.
Weighted-Average

30) Tabla de multiplicar interactiva
# Función que muestra la tabla de multiplicar del número introducido por el usuario.
function Multiplication-Table {
    # Solicitamos el número base para generar la tabla.
    $n = [int](Read-Host "Número base")
    # Iteramos del 1 al 10 mostrando el resultado de la multiplicación.
    for($i=1;$i -le 10;$i++){Write-Host "$n x $i = $($n*$i)"}
}
# Llamada para ejecutar la función y mostrar la tabla.
Multiplication-Table
