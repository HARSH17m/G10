from django.urls import path
from .views import *

urlpatterns = [
    path('',login,name="login"),
    path('signup/',signup,name="signup"),
    path('email-verify/',email_verify,name="email_verify"),
    path('details/<uuid:uid>/',details,name="details"),
    path('forgot-password/',forgot_password,name="forgot_password"),
    path('reset-password-logged-in/', lambda r: forgot_password(r, is_logged_in=True), name='password_reset_logged_in'),
    path('reset-password/',reset_password,name="reset_password"),
    path('index/',index,name="index"),
    path('profile/',profile,name="profile"),
    path('profile/update/',update_profile, name='update_profile'),
    path('member/',member, name='member'),
    path('member/user_verification/',user_verification, name='user_verification'),
    path('member/member_verification/',member_verification, name='member_verification'),
    path('member/<uuid:uid>/',member_page, name='member_page'),
    path('expense-tracker/',expense_tracker,name="expense_tracker"),
    path('shopping-list-and-bills/',shopping_list_and_bills,name="shopping_list_and_bills"),
    path('save_transactions/',save_transactions,name="save_transactions"),
    path('recent-expenses/',recent_expenses,name="recent_expenses"),
    path('analytics/',analytics,name="analytics"),
    path('contact_us/',contact_us, name='contact_us'),
    path('logout/',logout,name="logout"),
]
