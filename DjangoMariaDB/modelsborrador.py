# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models


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
