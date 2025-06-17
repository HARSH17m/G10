from django.urls import path
from .views import *

urlpatterns = [
    path('login/',login,name="login"),
    path('signup/',signup,name="signup"),
    path('details/',details,name="details"),
    path('index/',index,name="index"),
    path('analytics/',analytics,name="analytics"),
]
