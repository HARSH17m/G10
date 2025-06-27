from django.conf import settings
from django.core.mail import send_mail
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from django.db.models import Min, Max
from django.shortcuts import render,redirect
from django.utils.timezone import localtime,now,timedelta

from uuid import UUID # used to call object using str to uuid conversion
from decimal import Decimal 
from datetime import datetime

from .models import Users,UserDetails,UserSalary,Transaction,LogoutData
from .helpers import *

import random
import datetime

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
            user_id=user.UID,
            full_name=request.POST['full_name'],
            dob=request.POST['dob'],
            gender=request.POST['gender'],
            state=request.POST['state'],
            city=request.POST['city'],
            occupation=request.POST['occupation'],
            is_filled=True,
        )
        messages.success(request, "Details submitted successfully. You can now log in.")
        return render(request,'expense/login.html',{'email':user.email})
    INDIAN_STATES = [
    "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh",
    "Goa", "Gujarat", "Haryana", "Himachal Pradesh", "Jharkhand",
    "Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur",
    "Meghalaya", "Mizoram", "Nagaland", "Odisha", "Punjab",
    "Rajasthan", "Sikkim", "Tamil Nadu", "Telangana", "Tripura",
    "Uttar Pradesh", "Uttarakhand", "West Bengal",
    "Andaman and Nicobar Islands", "Chandigarh", "Dadra and Nagar Haveli and Daman and Diu",
    "Delhi", "Jammu and Kashmir", "Ladakh", "Lakshadweep", "Puducherry"]
    return render(request, 'expense/details.html', {'user': user,'states':INDIAN_STATES})

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

            request.session['reset_email'] = str(email_)

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
        return render(request,'expense/login.html',{'email':email_})
    return render(request,'expense/reset_password.html')

def index(request):
    return render(request,'expense/index.html')

def profile(request):
    user_uid = request.session.get('user_id')
    if not user_uid:
        messages.warning(request, "Please log in to view your recent expenses.")
        return redirect('login')
    user_instance=Users.objects.get(UID=UUID(user_uid))
    user_details, created = UserDetails.objects.get_or_create(
    user=user_instance,
    defaults={
        'full_name': '',
        'dob': '2000-01-01',  # default valid date
        'gender': '',
        'state': '',
        'city': '',
        'occupation': '',
        'is_filled': False
        }
    )
    gender_icon = {
        'male': 'bi-gender-male text-primary',
        'female': 'bi-gender-female text-danger',
    }.get(user_details.gender.lower(), 'bi-gender-ambiguous text-warning')
    data={
        'gender_icon':gender_icon,
        'user':user_instance,   
        'user_d':user_details
    }
    return render(request,'expense/profile.html',data)

def update_profile(request):
    user_uid = request.session.get('user_id')
    if not user_uid:
        messages.error(request, "Session not found please login")
        return redirect('login')
    
    user_details = UserDetails.objects.get(user_id=UUID(user_uid))
    
    if not user_details:
        messages.error(request, "Profile details not found.")
        return redirect('profile')

    if request.method == 'POST':
        user_details.full_name = request.POST.get('full_name')
        user_details.dob = request.POST.get('dob')
        user_details.gender = request.POST.get('gender')
        user_details.state = request.POST.get('state')
        user_details.city = request.POST.get('city')
        user_details.occupation = request.POST.get('occupation')
        user_details.save()
        messages.success(request, "Profile updated successfully.")
        return redirect('profile')
    INDIAN_STATES = [
    "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh",
    "Goa", "Gujarat", "Haryana", "Himachal Pradesh", "Jharkhand",
    "Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur",
    "Meghalaya", "Mizoram", "Nagaland", "Odisha", "Punjab",
    "Rajasthan", "Sikkim", "Tamil Nadu", "Telangana", "Tripura",
    "Uttar Pradesh", "Uttarakhand", "West Bengal",
    "Andaman and Nicobar Islands", "Chandigarh", "Dadra and Nagar Haveli and Daman and Diu",
    "Delhi", "Jammu and Kashmir", "Ladakh", "Lakshadweep", "Puducherry"]
    return render(request, 'expense/update_profile.html', {
        'user_details': user_details,
        'states':INDIAN_STATES,
    })

def expense_tracker(request):
    user_uid = request.session.get('user_id')
    if not user_uid:
        messages.warning(request, "Please log in to view your recent expenses.")
        return redirect('login')
    user_instance = Users.objects.get(UID=user_uid)
    user_details, created = UserDetails.objects.get_or_create(
    user=user_instance,
    defaults={
        'full_name': '',
        'dob': '2000-01-01',  # default valid date
        'gender': '',
        'state': '',
        'city': '',
        'occupation': '',
        'is_filled': False
        }
    )
    user_salary, created = UserSalary.objects.get_or_create(
        user=user_instance,
        defaults={
            'salary': 0,
            'saving': 0,
            'fixed_expenses': {},
            'emergency_percent': 10,
            'personal_percent': 40,
            'remaining_salary': 0,
            'reset_day': 1
        }
    )

    today_day = datetime.datetime.today().day
    is_reset_day = user_salary.reset_day == today_day
    is_first_time = created or (user_salary.salary == 0)

    # this is used to save data from form
    if request.method == 'POST' and (is_reset_day or is_first_time):
        salary = int(request.POST.get('salary', 0))
        saving = int(request.POST.get('saving', 0))
        emergency_percent = int(request.POST.get('emergency_percent', 10))
        personal_percent = int(request.POST.get('personal_percent', 40))
        reset_day = int(request.POST.get('reset_day', 1))
        fixed_expenses_raw = request.POST.get('fixed_expenses', '{}')

        import json
        fixed_expenses = json.loads(fixed_expenses_raw)
        
        user_salary.salary = salary
        user_salary.saving = saving
        user_salary.emergency_percent = emergency_percent
        user_salary.personal_percent = personal_percent

        user_salary.reset_day = reset_day

        user_salary.fixed_expenses = fixed_expenses
        user_salary.remaining_salary = user_salary.calculate_remaining()
        
        user_salary.save()
        return redirect('expense_tracker')

    show_popup = is_first_time or is_reset_day
    allow_edit = is_first_time or is_reset_day

    context = {
        'user':user_instance,
        'userd':user_details,
        'is_employed': user_details.occupation == 'Employed',
        'show_popup': show_popup,
        'user_salary': user_salary,
        'range_1_28': range(1, 29),
        'allow_edit': allow_edit,
    }
    return render(request, 'expense/expense_tracker.html', context)

def analytics(request):
    user_uid = request.session.get('user_id')
    if not user_uid:
        messages.warning(request, "Please log in to view your recent expenses.")
        return redirect('login')

    user = UserSalary.objects.get(user=UUID(user_uid))
    emf= user.salary * user.emergency_percent // 100
    # Dictionary of groups and their values
    all_groups = {
        'Savings': user.saving,
        'Emergency Funds': emf,
    }

    selected_group = request.POST.get('group')
    inflation_val = float(request.POST.get('inflation', 0)) if request.method == 'POST' else 0

    chart_data = {}
    if selected_group:
        base_val = all_groups.get(selected_group, 0)
        chart_data = {
        "1-Month Projection": {
        "labels": ["1W", "2W", "3W",],
        "base_values": [
            base_val * 1,
            base_val * 2,
            base_val * 3
        ],
        "inflated_values": [
            base_val * 1 * (1 + (inflation_val * 1 / 100)),
            base_val * 2 * (1 + (inflation_val * 2 / 100)),
            base_val * 3 * (1 + (inflation_val * 3 / 100))
        ]
    },
        "3-Month Projection": {
        "labels": ["Jan", "Feb", "Mar"],
        "base_values": [
            base_val * 1,
            base_val * 2,
            base_val * 3
        ],
        "inflated_values": [
            base_val * 1 * (1 + (inflation_val * 1 / 100)),
            base_val * 2 * (1 + (inflation_val * 2 / 100)),
            base_val * 3 * (1 + (inflation_val * 3 / 100))
        ]
    },
        "1-Year Projection": {
        "labels": ["Jan-Mar","Apr-Jun","Jul-Sep","Oct-Dec",],
        "base_values": [
            base_val * 1,
            base_val * 4,
            base_val * 7,
            base_val * 10,
        ],
        "inflated_values": [
            base_val * 1 * (1 + (inflation_val * 1 / 100)),
            base_val * 4 * (1 + (inflation_val * 4 / 100)),
            base_val * 7 * (1 + (inflation_val * 7 / 100)),
            base_val * 10 * (1 + (inflation_val * 10 / 100)),
        ]
    },
        "5-Year Projection": {
        "labels": ["1 Y", "2 Y", "3 Y", "4 Y", "5 Y"],
        "base_values": [
            base_val * 12 * 1,
            base_val * 12 * 2,
            base_val * 12 * 3,
            base_val * 12 * 4,
            base_val * 12 * 5
        ],
        "inflated_values": [
            base_val * 12 * 1 * (1 + (inflation_val * 12 / 100)),
            base_val * 12 * 2 * (1 + (inflation_val * 24 / 100)),
            base_val * 12 * 3 * (1 + (inflation_val * 36 / 100)),
            base_val * 12 * 4 * (1 + (inflation_val * 48 / 100)),
            base_val * 12 * 5 * (1 + (inflation_val * 60 / 100))
        ]
    }
    }

    return render(request, 'expense/analytics.html', {
        'all_groups': all_groups,              # Dictionary of group:value
        'group_keys': all_groups.keys(),       # For use in dropdown
        'selected_group': selected_group,
        'inflation_val': inflation_val,
        'chart_data': chart_data
    })

def shopping_list_and_bills(request):
    user_uid = request.session.get('user_id')
    if not user_uid:
        messages.warning(request, "Please log in to view your recent expenses.")
        return redirect('login')
    # if request.user.is_authenticated:
    # else:
    #     unshopped_items = []
    
    unshopped_items = request.session.get(f'unshopped_items_{user_uid}')

    if not unshopped_items:
        logout_data = LogoutData.objects.filter(user=UUID(user_uid), was_shopped=False)
        unshopped_items = [
            {
                'item': item.item_name,
                'expected': str(item.expected_amount),
                'paid': str(item.paid_amount)
            } for item in logout_data
        ]
        logout_data.delete()

    request.session[f'unshopped_items_{user_uid}'] = unshopped_items

    return render(request,'expense/shopping_list_and_bills.html',{"unshopped_items":unshopped_items})

def save_transactions(request,from_logout=False):
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
                unshopped_item = {
                    'item': item,
                    'expected': str(expected),
                    'paid': str(paid)
                }
                unshopped_items.append(unshopped_item)

                # save to LogoutData DB
                LogoutData.objects.create(
                    user=user,
                    item_name=item,
                    expected_amount=expected,
                    paid_amount=paid,
                    was_shopped=False
                )

            index += 1

        # Optionally: Store unshopped items in session to prefill later
        request.session[f'unshopped_items_{uid_str}'] = unshopped_items
        
        if from_logout:
            return True
        else:
            if transaction_count > 0:
                messages.success(request, f"{transaction_count} item(s) saved successfully.")
            else:
                messages.info(request, "No items were marked as shopped.")

            return redirect('shopping_list_and_bills')

    return redirect('shopping_list_and_bills')

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

    group_filter = request.GET.get('group')
    date_filter = request.GET.get('month_year')
    max_price = request.GET.get('price_max')

    if group_filter and group_filter != 'all':
        expenses = expenses.filter(group_name=group_filter)
    
    if date_filter:
        date_obj = datetime.strptime(date_filter, '%Y-%m')
        expenses = expenses.filter(
            transaction_time__year=date_obj.year,
            transaction_time__month=date_obj.month
        )

    if max_price:
        expenses = expenses.filter(paid_amount__lte=Decimal(max_price))

    # For sorting UI options
    all_groups = Transaction.objects.filter(user_id=user_uid).values_list('group_name', flat=True).distinct()
    all_groups = [g for g in all_groups if g]

    month_years = Transaction.objects.filter(user_id=user_uid).dates('transaction_time', 'month', order='DESC')
    price_range = Transaction.objects.filter(user_id=user_uid).aggregate(min_price=Min('paid_amount'), max_price=Max('paid_amount'))

    # Set defaults for display
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
        if save_transactions(request, from_logout=True):
            request.session.flush()
            messages.success(request, "Transactions saved. Logged out successfully.")
        else:
            request.session.flush()
            messages.warning(request, "Logged out, but some transactions may not have been saved.")
    return redirect('login')