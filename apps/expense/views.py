from django.shortcuts import render,redirect
from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import send_mail
from django.conf import settings

from .models import Users
from .helpers import *

import random

# Create your views here.
# def login_required(view_func):
#     @wraps(view_func)
#     def wrapper(request, *args, **kwargs):
#         if 'user_id' not in request.session:
#             return redirect('login')  # redirect to login page
#         return view_func(request, *args, **kwargs)
    # return wrapper 

def login(request):#VIVEK
    if request.method == 'POST':
        email_=request.POST['email']
        password_=request.POST['password']
        #
        if not Users.objects.filter(email=email_).exists():
            print("Email does't exist")
            return redirect('login')
        
        get_user = Users.objects.get(email=email_)

        if not get_user.is_active:
            print("Your account is deactive please contact to customer care")
            return redirect('login')
        
        is_password_verify = check_password(password_, get_user.password)
        if not is_password_verify:
            print("Email or password not match")
            return redirect('login') 
        
        request.session['user_id'] = str(get_user.UID)
        return redirect('index')
        #
    return render(request,'expense/login.html')

def signup(request):#ADAM
    if request.method == 'POST':
        email_=request.POST['email']
        password_=request.POST['password']
        confirm_password_=request.POST['confirm_password']
        #
        if not is_email_verified:
            print("Invalid email ")
            return redirect('signup')

        if Users.objects.filter(email=email_).exists():
            print("Email already exist")
            return redirect('signup')

        if password_ != confirm_password_:
            print("Password does not match")
            return redirect('signup')

        if not is_valid_password(password_)[0]:
            print(is_valid_password(password_)[1])
            return redirect('signup')
        
        otp_ = random.randint(111111,999999)

        user = Users(
            email=email_,
            password=make_password(password_),
            otp=otp_
        )
        subject = "Email Confirmation mail | Expenseo"
        message = f"OTP | {otp_}"
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [f"{email_}"]
        if send_mail(subject,message,from_email,recipient_list):
            print("Email Sent")
            user.save()
            context={
                'email':email_
            }
            return render(request,'expense/email_verify.html',context)
        #        
    return render(request,'expense/signup.html')

def email_verify(request):#VARUN
    if request.method == 'POST':
        email_=request.POST['email']
        otp_=request.POST['otp']
        #
        user = Users.objects.get(email=email_)

        if int(otp_) != int(user.otp):
            print(user.otp)
            print(otp_)
            print("Invalid OTP")
            context = {
            'email': email_
            }
            return render(request,'expense/email_verify.html', context)

        user.is_active = True
        user.save()
        return redirect('login')
        #
    return render(request,'expense/email_verify.html')

def forgot_password(request):  # HARSH
    if request.method == 'POST':
        email_ = request.POST['email']

        if not Users.objects.filter(email=email_).exists():
            print("Email doesn't exist")
            return redirect('signup')

        if 'send_otp' in request.POST:
            forgot_password_otp_ = random.randint(111111, 999999)

            user = Users.objects.get(email=email_)
            user.forgot_password_otp = forgot_password_otp_
            user.save()

            request.session['reset_email'] = email_

            subject = "OTP for Resetting Password | Expenseo"
            message = f"OTP for Verification: {forgot_password_otp_}"
            from_email = settings.EMAIL_HOST_USER
            recipient_list = [email_]

            send_mail(subject, message, from_email, recipient_list)

            print("OTP Sent")
            return render(request, 'expense/forgot_password.html', {
                'email': email_,
                'otp_sent': True
            })

        elif 'verify_otp' in request.POST:
            user_otp = request.POST['otp']
            email_ = request.session.get('reset_email')

            if not email_:
                return redirect('forgot_password')

            user = Users.objects.get(email=email_)

            if int(user_otp) != int(user.forgot_password_otp):
                print("Invalid OTP")
                return render(request, 'expense/forgot_password.html', {
                    'email': email_,
                    'otp_sent': True,
                    'error': 'Invalid OTP. Please try again.'
                })

            print("OTP Verified")
            return render(request, 'expense/reset_password.html', {
                'email': email_
            })

    return render(request, 'expense/forgot_password.html')

def reset_password(request):
    if request.method == 'POST':
        email_ = request.POST['email']
        password_ = request.POST['password']
        confirm_password_ = request.POST['confirm_password']
        
        if password_ != confirm_password_:
            print("Password does not match")
            return render(request,'expense/reset_password.html',{'email':email_})
        
        if not is_valid_password(password_)[0]:
            print(is_valid_password(password_)[1])
            return render(request,'expense/reset_password.html',{'email':email_})
        
        user=Users.objects.get(email=email_)
        user.password=make_password(password_)
        print("Password Updated Successfully")
        user.save()
        return redirect('login')
    return render(request,'expense/reset_password.html')

# @login_required
def index(request):
    return render(request,'expense/index.html')
 
def analytics(request):
    return render(request,'expense/analytics.html')

def details(request):
    return render(request,'expense/details.html')

def shopping_list_and_bills(request):
    return render(request,'expense/shopping_list_and_bills.html')

def recent_expenses(request):#HARSH
    return render(request,'expense/recent_expenses.html')
