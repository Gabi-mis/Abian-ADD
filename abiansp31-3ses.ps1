# abiansp31-3ses.ps1
# Uso: .\abiansp31-3ses.ps1 "2025-11-01" "2025-11-10"

#pido las fechas de inicio y fin
$FechaInicio = Read-Host "Introduce la fecha de inicio (ejemplo: 2025-11-01)"
$FechaFin    = Read-Host "Introduce la fecha de fin (ejemplo: 2025-11-10)"

Write-Host "Eventos de Inicio de Sesión:`n" -ForegroundColor Cyan

#hacemos un filtrado de logs para solo usar inicos de sesion luego cogemos los logs que estan entre las dos fechas pedidas anteriormente
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$FechaInicio; EndTime=$FechaFin} |
#uso un foreach para extraer los valores de usuario y la fecha y hora del inicio y guardarlos en estas dos variables 
    ForEach-Object {
        $usuario = $_.Properties[5].Value
        $hora = $_.TimeCreated

        # descartamos los usuarios creados por sistema como los usuarios de servicios o WIN-7462D23KU4H$ y dejamos solo los que tienen cuentas
        # asociadas a usuarios reales como el usuario administrador
        if ($usuario -and
            $usuario -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|DWM.*|UMFD.*|SERVICIO LOCAL|Servicio de red)$' -and
            $usuario -notmatch '\$$') {

            #ahora se muestra a continuacion la informacion anterior
            Write-Host ("Fecha: {0} {1} - Usuario: {2}" -f `
                $hora.ToString("MM/dd/yyyy"), `
                $hora.ToString("HH:mm:ss"), `
                $usuario) -ForegroundColor green
        }
    }

