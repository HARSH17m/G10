from django.contrib import admin
from .models import Users,UserDetails,UserSalary,Member,Transaction,LogoutData

# Register your models here.
admin.site.register(Users)
admin.site.register(UserSalary)
admin.site.register(UserDetails)
admin.site.register(Member)
admin.site.register(LogoutData)
admin.site.register(Transaction)