from django.conf import settings
from django.core.mail import send_mail
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from django.db.models import Min, Max
from django.shortcuts import render,redirect
from django.utils.timezone import localtime,now,timedelta

from functools import wraps
from uuid import UUID
from decimal import Decimal
from datetime import datetime

from .models import Users,UserDetails,Transaction
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
            messages.error(request, "This email is not registered.")
            return redirect('login')
        
        get_user = Users.objects.get(email=email_)

        if not get_user.is_active:
            messages.warning(request, "Your account is inactive. Please contact support.")
            return redirect('login')
        
        is_password_verify = check_password(password_, get_user.password)
        if not is_password_verify:
            messages.error(request, "Incorrect email or password.")
            return redirect('login') 
        
        request.session['user_id'] = str(get_user.UID)
        messages.success(request, "Login successful!")
        return redirect('index')
        #
    return render(request,'expense/login.html')

def signup(request):#ADAM,
    if request.method == 'POST':
        email_=request.POST['email']
        password_=request.POST['password']
        confirm_password_=request.POST['confirm_password']
        #
        if not is_email_verified:
            messages.error(request, "Email verification failed. Please try again.")
            return redirect('signup')

        if Users.objects.filter(email=email_).exists():
            messages.warning(request, "This email is already registered.")
            return redirect('signup')

        if password_ != confirm_password_:
            messages.error(request, "Passwords do not match.")
            return redirect('signup')

        if not is_valid_password(password_)[0]:
            messages.error(request,is_valid_password(password_)[1])
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
            messages.info(request, "OTP sent to your email.")
            user.save()
            context={
                'email':email_
            }
            return render(request,'expense/email_verify.html',context)
        else:
            messages.error(request, "Failed to send OTP. Please try again.")
        #        
    return render(request,'expense/signup.html')

def email_verify(request):#VARUN
    if request.method == 'POST':
        email_=request.POST['email']
        otp_=request.POST['otp']
        #
        user = Users.objects.get(email=email_)

        if int(otp_) != int(user.otp):
            messages.error(request, "Invalid OTP. Please try again.")
            context = {
            'email': email_
            }
            return render(request,'expense/email_verify.html', context)

        user.is_active = True
        user.save()
        messages.success(request, "Email verified successfully. You can now log in.")
        return redirect('details', uid=user.UID)
        #
    return render(request,'expense/email_verify.html')

def details(request, uid):
    user = Users.objects.filter(UID=uid,is_active=True).first()
    if not user:
        messages.error(request, "Invalid or inactive user.")
        return redirect('register')

    if UserDetails.objects.filter(user_id=user).exists():
        messages.info(request, "Details already submitted. You can log in now.")
        return redirect('login')  # already filled

    if request.method == 'POST':
        UserDetails.objects.create(
            user_id=user,
            full_name=request.POST['full_name'],
            dob=request.POST['dob'],
            gender=request.POST['gender'],
            state=request.POST['state'],
            city=request.POST['city'],
            occupation=request.POST['occupation']
        )
        messages.success(request, "Details submitted successfully. You can now log in.")
        return redirect('login')

    return render(request, 'details.html', {'user': user})

def forgot_password(request): # HARSH
    if request.method == 'POST':
        email_ = request.POST['email']

        if not Users.objects.filter(email=email_).exists():
            messages.warning(request, "Email not found. Please sign up.")
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
            messages.info(request, "OTP has been sent to your email.")

            return render(request, 'expense/forgot_password.html', {
                'email': email_,
                'otp_sent': True
            })

        elif 'verify_otp' in request.POST:
            user_otp = request.POST['otp']
            email_ = request.session.get('reset_email')

            if not email_:
                messages.error(request, "Session expired. Please try again.")
                return redirect('forgot_password')

            user = Users.objects.get(email=email_)

            if int(user_otp) != int(user.forgot_password_otp):
                messages.error(request, "Invalid OTP. Please try again.")
                return render(request, 'expense/forgot_password.html', {
                    'email': email_,
                    'otp_sent': True,
                    'error': 'Invalid OTP. Please try again.'
                })

            messages.success(request, "OTP verified. You can now reset your password.")
            return render(request, 'expense/reset_password.html', {
                'email': email_
            })

    return render(request, 'expense/forgot_password.html')

def reset_password(request): # HARSH
    if request.method == 'POST':
        email_ = request.POST['email']
        password_ = request.POST['password']
        confirm_password_ = request.POST['confirm_password']
        
        if password_ != confirm_password_:
            messages.error(request, "Passwords do not match.")
            return render(request,'expense/reset_password.html',{'email':email_})
        
        if not is_valid_password(password_)[0]:
            messages.error(request,is_valid_password(password_)[1])
            return render(request,'expense/reset_password.html',{'email':email_})
        
        user=Users.objects.get(email=email_)
        user.password=make_password(password_)
        user.save()
        messages.success(request, "Password updated successfully. Please log in.")
        return redirect('login')
    return render(request,'expense/reset_password.html')

# @login_required
def index(request):
    return render(request,'expense/index.html')
 
def analytics(request):
    return render(request,'expense/analytics.html')

def shopping_list_and_bills(request):
    user_uid = request.session.get('user_id')
    if not user_uid:
        messages.warning(request, "Please log in to view your recent expenses.")
        return redirect('login')

    unshopped_key = f'unshopped_items_{user_uid}'
    unshopped_items = request.session.get(unshopped_key, [])
    return render(request,'expense/shopping_list_and_bills.html',{"unshopped_items":unshopped_items})

def save_transactions(request):
    if request.method == 'POST':
        uid_str = request.session.get('user_id')
        if not uid_str:
            messages.error(request, "Session expired. Please log in again.")
            return redirect('login')
        
        user = Users.objects.get(UID=UUID(uid_str))
        unshopped_items = []
        transaction_count = 0

        index = 0
        while True:
            item_key = f'item_{index}'
            expected_key = f'expected_{index}'
            paid_key = f'paid_{index}'
            shopped_key = f'shopped_{index}'

            item = request.POST.get(item_key)
            expected = request.POST.get(expected_key)
            paid = request.POST.get(paid_key)
            shopped = request.POST.get(shopped_key)

            if item is None and expected is None and paid is None:
                break

            if shopped:
                Transaction.objects.create(
                    user=user,
                    item_name=item,
                    expected_amount=expected or 0,
                    paid_amount=paid or 0,
                )
                transaction_count += 1
            else:
                unshopped_items.append({
                    'item': item,
                    'expected': expected,
                    'paid': paid,
                })

            index += 1

        # Optionally: Store unshopped items in session to prefill later
        request.session[f'unshopped_items_{uid_str}'] = unshopped_items

        if transaction_count > 0:
            messages.success(request, f"{transaction_count} item(s) saved successfully.")
        else:
            messages.info(request, "No items were marked as shopped.")

        return redirect('shopping_list_and_bills')

    return redirect('shopping_list_and_bills')

# def recent_expenses(request):#HARSH
#     user_uid = request.session.get('user_id')

#     if not user_uid:
#         messages.warning(request, "Please log in to view your recent expenses.")
#         return redirect('login')  # or your preferred login route

#     # Fetch user's transactions, newest first
#     expenses = Transaction.objects.filter(user_id=user_uid).order_by('-transaction_time')

#     # Optional: Format date if needed in view instead of template
#     for e in expenses:
#         e.formatted_date = localtime(e.transaction_time).strftime('%d-%b-%Y')

#     return render(request, 'expense/recent_expenses.html', {
#         'expenses': expenses
#     })

def recent_expenses(request):
    user_uid = request.session.get('user_id')
    if not user_uid:
        messages.warning(request, "Please log in to view your recent expenses.")
        return redirect('login')

    # ----------------------------
    # Handle POST (Group + Notes)
    # ----------------------------
    if request.method == 'POST':
        selected_ids = request.POST.getlist('selected')  # list of transaction UIDs
        group_name = request.POST.get('group_name', '').strip()
        
        # Update group for selected transactions
        if selected_ids and group_name:
            Transaction.objects.filter(user_id=user_uid, UID__in=selected_ids).update(group_name=group_name)

        # Update notes
        for key in request.POST:
            if key.startswith('note_'):
                tx_id = key.split('_')[1]
                note_text = request.POST.get(key, '')[:100]
                Transaction.objects.filter(user_id=user_uid, UID=tx_id).update(note=note_text)

        return redirect('recent_expenses')

    # ----------------------------
    # Handle GET (Filtering)
    # ----------------------------
    expenses = Transaction.objects.filter(user_id=user_uid).order_by('-transaction_time')

    # Filters
    group_filter = request.GET.get('group')
    date_filter = request.GET.get('month_year')
    max_price = request.GET.get('price_max')

    if group_filter and group_filter != 'all':
        expenses = expenses.filter(group_name=group_filter)
    
    if date_filter:
        try:
            date_obj = datetime.strptime(date_filter, '%Y-%m')
            expenses = expenses.filter(
                transaction_time__year=date_obj.year,
                transaction_time__month=date_obj.month
            )
        except:
            pass

    if max_price:
        try:
            expenses = expenses.filter(paid_amount__lte=Decimal(max_price))
        except:
            pass

    # For sorting UI options
    all_groups = Transaction.objects.filter(user_id=user_uid).values_list('group_name', flat=True).distinct()
    all_groups = [g for g in all_groups if g]  # remove nulls

    month_years = Transaction.objects.filter(user_id=user_uid).dates('transaction_time', 'month', order='DESC')
    price_range = Transaction.objects.filter(user_id=user_uid).aggregate(min_price=Min('paid_amount'), max_price=Max('paid_amount'))

    # Set defaults if null
    for e in expenses:
        if not e.group_name:
            e.group_name = "Ungrouped"
        if not e.note:
            e.note = "None"
        e.formatted_date = localtime(e.transaction_time).strftime('%d-%b-%Y')

    return render(request, 'expense/recent_expenses.html', {
        'expenses': expenses,
        'groups': all_groups,
        'month_years': month_years,
        'price_range': price_range
})


def dashboard_view(request):
    if not request.session.get('user_email'):
        return redirect('login')

    user = Users.objects.get(email=request.session['user_email'])
    all_groups = Transaction.objects.filter(user=user).exclude(group_name=None).values_list('group_name', flat=True).distinct()

    selected_group = None
    inflation = 0.0
    chart_data = {}  # {'1M': [...], '6M': [...], '1Y': [...], '5Y': [...]}

    # Time range mappings
    range_map = {
        '1M': now() - timedelta(days=30),
        '6M': now() - timedelta(days=180),
        '1Y': now() - timedelta(days=365),
        '5Y': now() - timedelta(days=5 * 365),
    }

    if request.method == 'POST':
        selected_group = request.POST.get('group')
        inflation = float(request.POST.get('inflation', 0)) / 100

        for label, date_from in range_map.items():
            transactions = Transaction.objects.filter(
                user=user,
                group_name=selected_group,
                transaction_time__gte=date_from
            ).order_by('transaction_time')

            chart_data[label] = [
                {
                    "label": t.transaction_time.strftime('%Y-%m-%d'),
                    "value": round(float(t.paid_amount) * ((1 + inflation) ** ((now() - t.transaction_time).days / 365)), 2)
                } for t in transactions
            ]

    return render(request, 'dashboard.html', {
        "all_groups": all_groups,
        "chart_data": chart_data,
        "selected_group": selected_group,
        "inflation_val": int(inflation * 100),
    })

def logout(request):
    if 'user_id' in request.session:
        request.session.flush()
        messages.success(request, "Logged out successfully.")
    else:
        messages.info(request, "You were not logged in.")
    return redirect('login')

# def logout(request):
    user_uid = request.session.get('user_id')
    if not user_uid:
        return redirect('login')

    uid = UUID(user_uid)

    unshopped_key = f'unshopped_items_{user_uid}'
    unshopped_items = request.session.get(unshopped_key, [])

    # Save unshopped items
    for item in unshopped_items:
        LogoutData.objects.create(
            user_id=uid,
            item_name=item['item'],
            expected_amount=item['expected'] or 0,
            paid_amount=item['paid'] or 0,
            was_shopped=False
        )

    shopped_items = request.session.get(f'shopped_items_{user_uid}', [])
    for item in shopped_items:
        LogoutData.objects.create(
            user_id=uid,
            item_name=item['item'],
            expected_amount=item['expected'] or 0,
            paid_amount=item['paid'] or 0,
            was_shopped=True
        )

    request.session.flush()
    messages.success(request, "Session ended. Data stored safely.")
    return redirect('login')