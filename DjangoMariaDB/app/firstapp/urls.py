from django.urls import path

from . import views

urlpatterns = [
    path('client/login',views.login,name='login'),
    path('generate_password/<str:password>',views.makepassword,name='makepassword'),
    path('client/movies',views.showmovielist,name='showmovielist'),
    path('',views.vista,name='vista'),
    path('dos',views.vista2,name='vista2')
]
