from django.contrib import admin
from .models import Users,Transaction,UserDetails

# Register your models here.
admin.site.register(Users)
admin.site.register(UserDetails)
admin.site.register(Transaction)