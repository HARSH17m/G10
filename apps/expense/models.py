from django.db import models

# Create your models here.
class Users(models.Model):
    name=models.TextField
    email=models.EmailField(max_length=255,null=False,blank=False)
    password=models.CharField(max_length=255,null=False,blank=False)
    is_active=models.BooleanField(default=False)