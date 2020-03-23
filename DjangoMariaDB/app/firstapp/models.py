from django.db import models

# Create your models here.
class Estados(models.Model):
    clave = models.CharField(max_length=2)
    name = models.CharField(max_length=45)
    abrev = models.CharField(max_length=16)
    abrev_pm = models.CharField(max_length=16)
    id_country = models.IntegerField(blank=True, null=True)
    risk = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'estados'

class ApiUsers(models.Model):
    user = models.CharField(max_length=250)
    password = models.CharField(max_length=250)
    api_key = models.CharField(max_length=250, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'api_users'

class Movie(models.Model):
    movieid = models.CharField(db_column='MovieID', primary_key=True, max_length=10)  # Field name made lowercase.
    movietitle = models.CharField(db_column='MovieTitle', max_length=30)  # Field name made lowercase.
    releasedate = models.DateField(db_column='ReleaseDate')  # Field name made lowercase.
    genereid = models.CharField(db_column='GenereID', max_length=10, blank=True, null=True)  # Field name made lowercase.
    directorid = models.CharField(db_column='DirectorID', max_length=10, blank=True, null=True)  # Field name made lowercase.
    imageurl = models.CharField(db_column='ImageUrl', max_length=250)  # Field name made lowercase.
    description = models.CharField(db_column='Description', max_length=250)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'movie'


#from rest_framework import serializers

#class PaymentSerializer(serializers.Serializer):
    #amount = serializers.IntegerField(required=True, min_value=0)
    #name = serializers.CharField(required=True, max_length=128)
    #type = serializers.IntegerField(required=True, min_value=0)

#class ValidateFormSerializer(serializers.Serializer):
    #var1 = serializers.CharField(required=True, max_length=250)
    #var2 = serializers.CharField(required=True, max_length=250)
    #payments = serializers.ListField(child=PaymentSerializer)
