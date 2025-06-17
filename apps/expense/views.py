from django.shortcuts import render,redirect

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