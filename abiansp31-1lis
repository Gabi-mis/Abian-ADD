# nombresp31-1lis.ps1
# Menú de eventos del sistema
#creo una variable para hacer de accion en el menu
$op = ""
#bucle que muestra el menu y cada vez que se reinicie se limpiara la terminal
while ($op -ne "0") {
   Clear-Host
    Write-Host "====== MENU ======"
    Write-Host "1 - Listado eventos del sistema"
    Write-Host "2 - Errores del último mes"
    Write-Host "3 - Warnings de aplicaciones esta semana"
    Write-Host "0 - Salir"
#pido al usuario que seleccione una de las opciones del menu
    $op = Read-Host "Selecciona una opción"

#switch que interpreta la eleccion del usuario
    switch ($op) {
        "1" { 
#muestro los 20 ultimos registros de eventos del sistema mediante el comando get-eventlog el cual coge estos registros del visor de eventos luego esta el comando pause que pone una pausa cuando muestra el registro sugerido para continuar dale a enter
                Write-Host "`n--- Listado de eventos del sistema ---`n"
                Get-EventLog -LogName System -Newest 20 
                Pause 
                }

        "2" { 
#muestro los 20 primeros resultados de un filtrado de nuevo sacado con el comando get-eventlog que pilla los registros del visor de eventos el filtrado guarda en una variable el mes pasado y coge los registros con la palabra error y comparando las fechas coge desde esa fecha en adelante por ejemplo si estamos a 1 de abril y ejecutamos el codigo pillara los registros de error de 1 de marzo al 1 de abril luego esta el comando pause que pone una pausa cuando muestra el registro sugerido para continuar dale a enter
              Write-Host "`n--- Errores del sistema en el mes pasado ---`n"
              $fecha = (Get-Date).AddMonths(-1)
              Get-EventLog -LogName System | Where-Object { $_.EntryType -eq "Error" -and $_.TimeGenerated -ge $fecha } | Select -First 20
              Pause 
              }

        "3" { 
#este es muy parecido al anterior pero en vez de pillar errores del sistema pilla warnings de aplicaciones y cambiamos el uso de la seleccion de fecha para que pille los warnings de hace 7 dias en adelante tambien lo limita a los 20 primeros registros tambien tiene el pause que ya lo he explicado
              Write-Host "`n--- Warnings de aplicaciones de esta semana ---`n"
              $fecha = (Get-Date).AddDays(-7)
              Get-EventLog -LogName Application | Where-Object { $_.EntryType -eq "Warning" -and $_.TimeGenerated -ge $fecha } | Select -First 20
              Pause 
              }

#añado una cuarta opcion que es la salida
        "0" { Write-Host "Saliendo..." }
#y añado una ultima que se tomara en caso de que se ponga cualquier otra cosa y dara un error de opcion invalida
        default { Write-Host "Opción no válida"; Pause }
    }
}
