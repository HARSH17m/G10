from django.urls import path
from .views import *

urlpatterns = [
    path('login/',login,name="login"),#VIVEK
    path('',signup,name="signup"),#ADAM
    path('email-verify/',email_verify,name="email_verify"),#VARUN
    path('forgot-password/',forgot_password,name="forgot_password"),#HARSH
    path('details/',details,name="details"),
    path('index/',index,name="index"),
    path('analytics/',analytics,name="analytics"),
]
