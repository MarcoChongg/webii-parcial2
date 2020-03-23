#1 we need to build our custom image that has Python, Django and mysqlconnector for mysql support.
ssh > docker build .

#2 we need to build a version of the container to run a command needed to start django.
ssh > docker-compose build

#3 before run the server, we need to create a project with the name apirest. THIS ITS ONLY FOR THE FTS TIME
ssh > docker-compose run app sh -c "django-admin.py startproject apirest ."

#4 We start our contaier and automatically it will start our server
ssh > docker-compose up

#5 check if server is running
type http://localhost/ or http://127.0.0.1 in your explorer address bar.

#5 we have to know our container name that can be found on the NAMES column
ssh > docker ps

#6 Create of first app
docker exec container_name python manage.py startapp firstapp

#7 Open the file firstapp/views.py and put the following Python code in it:

from django.http import HttpResponse

def index(request):
    return HttpResponse("Hello, world.")

#8 Create a file called urls.py and include the following code:
from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
]

#9 On apirest/urls.py, add an import for django.urls.include and insert an include() in the urlpatterns list, so you have:
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('1.0/', include('firstapp.urls')),
    path('admin/', admin.site.urls),
]

#10 check if server is running
type http://localhost/1.0/ or http://127.0.0.1/1.0/ in your address bar.

#DOCKER MARIADB CONTAINER COMMAND
#docker run -d --name mariadbservices -p 34672:3306 -v /var/db2/config:/etc/mysql/conf.d -v /var/db2/datadir:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=yuy34234NlbWlDWX1ufDr8E2343PRjjAxe -e MYSQL_DATABASE=services mariadb/server:10.3

#ACCESS TO DATABASE SHELL
docker exec -it containername bash

#IMPORT SQL BACKUP FILE
docker exec -i dbcontainername mysql -u username -ppassword --default-character-set=utf8  databasename < file_location

#MIGRATE Database
docker exec containername python manage.py inspectdb > models.py

#APPLY MODELDS
docker exec containername python manage.py makemigrations

docker exec containername python manage.py migrate



cmd /c --% docker exec -i 0666ae9b982e mysql -u dbuser -pUsr@2020.. --default-character-set=utf8  dbapi < D:\DjangoMariaDB\api_users.sql

docker exec 60aa3b8d3d13 python manage.py makemigrations

docker exec 60aa3b8d3d13 python manage.py migrate

PASOS PARA CREAR UN API
#1 CREAR IMAGEN Y REPOSITORIO

#2 CONFIGURAR DJANGO CON MYSQL

#3 CREAR NUESTROS ENDPOINTS

#4 CREAR VISTAS

#5 VALIDAR MÉTODOS

#6 VALIDAR BODY/JSON

#6 REALIZAR ACCIONES ESPECÍFICAS PARA CADA ENDPOINT

#7 IMPLEMENTACIÓN
