from django.shortcuts import render,redirect
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.conf import settings

from .helpers import *

import random

# Create your views here.
def login(request):
    return render(request,'expense/login.html')

def signup(request):
    return render(request,'expense/signup.html')

def index(request):
    return render(request,'expense/index.html')
 
def analytics(request):
    return render(request,'expense/analytics.html')

def details(request):
    return render(request,'expense/details.html')