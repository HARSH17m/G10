from django.shortcuts import render,redirect
from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import send_mail
from django.conf import settings

from .helpers import *

import random

# Create your views here.
def login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if 'labour_id' not in request.session:
            return redirect('login')  # redirect to login page
        return view_func(request, *args, **kwargs)
    return wrapper 

def login(request):#VIVEK
    if request.method == 'POST':
        email_=request.POST['email']
        password_=request.POST['password']
        
    return render(request,'expense/login.html')

def signup(request):#ADAM
    if request.method == 'POST':
        email_=request.POST['email']
        password_=request.POST['password']
        confirm_password_=request.POST['confirm_password']
        #

    return render(request,'expense/signup.html')

def email_verify(request):#VARUN
    if request.method == 'POST':
        email_=request.POST['email']
        otp_=request.POST['otp']
        #

    return render(request,'expense/email_verify.html')

def forgot_password(request):#HARSH
    return render(request,'expense/forgot_password.html')

def index(request):
    return render(request,'expense/index.html')
 
def analytics(request):
    return render(request,'expense/analytics.html')

def details(request):
    return render(request,'expense/details.html')
