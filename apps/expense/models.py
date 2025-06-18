from django.db import models
import uuid
# Create your models here.
class BaseClass(models.Model):
    UID=models.UUIDField(default=uuid.uuid4,primary_key=True,null=False,blank=False)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    class Meta:
        abstract =True
class Users(BaseClass):
    email=models.EmailField(max_length=255,null=False,blank=False)
    password=models.CharField(max_length=255,null=False,blank=False)
    is_active=models.BooleanField(default=False)

# class UserDetails(Users):
#     Uid=models.ForeignKey(Users,on_delete=models.CASCADE)

