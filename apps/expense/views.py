from django.shortcuts import render,redirect

# Create your views here.
def index(request):
    return render(request,'expense/index.html')
def analytics(request):
    return render(request,'expense/analytics.html')