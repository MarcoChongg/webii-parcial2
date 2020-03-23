#SEGUNDO PARCIAL

#1 Cargar tabla movies.sql y api_users.sql

#2 Migrar tablas para crear modelos (ya en proyeco)

#3 Crear modelo en models.py (ya en proyeco)

#4 realizar makemigrations y migrate

#5 Crear en la base de datos un usuario y su contraseña
Las contraseñas nunca se deben de guardar, lo que debemos de guardar es un Hash.
Este hash representa un string generado desde la contraseña orginal. Este no es una encriptación ya que cada vez que realizemos un password Hash este dará un resultado diferente.
Se utliza una funcion de comparación para saber si el Hash almacenado  y la contraseña que queremos validar dan un resultado positivo.
De esta manera si alguna persona roba nuestra base de datos, aún tenga el hash a la mano, le es imposible acceder a sus cuentas.

Cree un método para que crean una contraseña HASH
http://127.0.0.1/1.0/generate_password/suContraseña

Este les devolverá un Json con su Password Hash en el key password.

#6 Crear EndPoints basados en el API REFERENCE

#7 Realizar procesos basado en el API REFERENTE

#8 Enviar liga de GitHub con su proyecto con el EndPoint Login desarrollado antes del viernes 27 de Marzo

#9 20 de Marzo de 9:00 a.m. a 11:00 a.m. estaré en línea en skype para resolver dudas
