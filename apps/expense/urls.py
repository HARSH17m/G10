from django.urls import path
from .views import *

urlpatterns = [
    path('',login,name="login"),#VIVEK
    path('signup/',signup,name="signup"),#ADAM
    path('email-verify/',email_verify,name="email_verify"),#VARUN
    path('details/<uuid:uid>/',details,name="details"),
    path('index/',index,name="index"),
    path('analytics/',analytics,name="analytics"),
    path('shopping-list-and-bills/',shopping_list_and_bills,name="shopping_list_and_bills"),
    path('recent-expenses/',recent_expenses,name="recent_expenses"),
    path('forgot-password/',forgot_password,name="forgot_password"),#HARSH
    path('reset-password/',reset_password,name="reset_password"),
    path('logout/',logout,name="logout"),
    path('save_transactions/',save_transactions,name="save_transactions"),
]
