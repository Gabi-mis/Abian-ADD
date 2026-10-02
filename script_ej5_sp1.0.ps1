#creo una variable inicial para controlar las opciones del switch y el cierre del bucle.
$opcion = 0

#inicio del bucle y le pongo como condicion de continuacion del bucle que opcion distinto de 5 osea que si pongo 5 se cierra el bucle.
while ($opcion -ne 5) {
    Clear-Host
    Write-Host "1. Mostrar información del dominio"
    Write-Host "2. Crear una nueva Unidad Organizativa"
    Write-Host "3. Crear un nuevo grupo"
    Write-Host "4. Crear una nueva cuenta de usuario"
    Write-Host "5. Salir"
   
   #pongo un texto para hacer que el usuario pueda introducir la opcion que desee.
    $opcion = Read-Host "Selecciona una opción (1-5)"

    #inicio el switch y toma de variable de accion opcion como tal.
    switch ($opcion) {
        "1" {
            #muestro la informacion del dominio pedida en el supuesto si se escoge la opcion 1.
            Write-Host "=== INFORMACIÓN DEL DOMINIO ==="
            Write-Host "Nombre del equipo:  " $env:COMPUTERNAME
            Write-Host "Nombre del dominio: " (Get-ADDomain).Name
            Write-Host "Numero de OUs:      " @(Get-ADOrganizationalUnit -Filter *).Count
            Write-Host "Numero de Grupos:   " (Get-ADGroup -Filter *).Count
            Write-Host "Numero de Usuarios: " (Get-ADUser -Filter *).Count
           
            Pause
        }
        "2" {
            #pido el nombre de la unidad organizativa.
            $nombreOU = Read-Host "Nombre de la nueva OU"
           
            #crea la unidad organizativa con el nombre sugerido y muestro un mensaje confirmando que la creo.
            New-ADOrganizationalUnit -Name $nombreOU
            Write-Host "Unidad Organizativa '$nombreOU' creada correctamente."
           
            Pause
        }
        "3" {
            #pido el nombre del grupo, su tipo y categoria.
            $nombreGrupo = Read-Host "Nombre del nuevo Grupo"
            $tipoGrupo = Read-Host "tipo del nuevo Grupo (global, DomainLocal o universal)"
            $categoriaGrupo = Read-Host "categoria del nuevo Grupo (security o distribution)"

            #creo el grupo con los datos anteriores y escribo un mensaje de confirmacion por terminal.
            New-ADGroup -Name $nombreGrupo -GroupScope $tipoGrupo -GroupCategory $categoriaGrupo
            Write-Host "Grupo '$nombreGrupo' creado correctamente."
           
            Pause
        }
        "4" {
            #pido la informacion mas relevante del usuario.
            $nombreUsuario = Read-Host "Nombre del nuevo usuario"
            $grupoTarget = Read-Host "Grupo al que se asignará"
            $pass = Read-Host "Contraseña inicial" -AsSecureString
           
            #creo el usaurio usando la informacion obtenida anteriormente.
            New-ADUser -Name $nombreUsuario `
                       -SamAccountName $nombreUsuario `
                       -AccountPassword $pass `


            #asigno el usuario al grupo seleccionado anteriormente.
            Add-ADGroupMember -Identity $grupoTarget -Members $nombreUsuario
           
            Write-Host "Usuario '$nombreUsuario' creado y añadido al grupo '$grupoTarget'."
           
            Pause
        }
        "5" {
            #opcion para salir.
            Write-Host "Saliendo del programa..."
        }
        default {
            #opcion por si se usa informacion invalida.
            Write-Host "Opción no válida. Inténtalo de nuevo."
            Pause
        }
    }
}