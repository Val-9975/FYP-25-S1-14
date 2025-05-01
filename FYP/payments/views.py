import uuid
import threading
import time
import logging
import random
import re
from datetime import datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Sum
from .models import MerchantTransaction, LegacyUser, Transaction, UserAccountStatus, Complaint, TokenVault
from .forms import ComplaintForm
from django.db import transaction as db_transaction
from .forms import TicketUpdateForm
from .login import handle_login
from .logout import custom_logout
from decimal import Decimal, InvalidOperation
from .models import SecurityProtocol, SecurityProtocolDetail
from django.http import JsonResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.models import User
from .login import authenticate_user
from .forget_password import forgot_password
from .verifyOTP import verify_otp_user
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from .models import SavedPaymentMethod
from django.views.decorators.http import require_POST
from django.conf import settings
from django.urls import reverse
from .decorators import role_required, ROLE_CUSTOMER, ROLE_MERCHANT, ROLE_ADMIN, ROLE_HELPDESK


logger = logging.getLogger(__name__)

User = get_user_model()

def is_strong_password(password):
    """
    Returns (True, "") if password is strong,
    else returns (False, "error message")
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter (Eg. A,B,C...)."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter (Eg. a,b,c...)."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number (Eg. 1,2,3...)."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character (Eg. !,*,&...)."
    return True, ""

def create_user(request):

    if request.method == 'POST':
        # First, check if the user agreed to the security protocols
        agreement = request.POST.get('agree_terms')  # 'on' if checked, None otherwise
        if not agreement:
            messages.error(request, "Only if you agree to the protocols, then can an account be created.")
            #Re-render the form with the current protocols content
            protocol = SecurityProtocolDetail.objects.first()
            return render(request, 'createUsers.html', {'security_protocol': protocol})

        #collect form data
        email = request.POST.get('email')
        password = request.POST.get('password')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        phone_number = request.POST.get('phone_number')
        address = request.POST.get('address')
        city = request.POST.get('city')
        state = request.POST.get('state')
        country = request.POST.get('country')
        zip_code = request.POST.get('zip_code')

        # Set role_id based on user type (Customer: 1, Merchant: 2)
        role_id = request.POST.get('role')  # Get role_id from form input

        # Validate Password
        is_valid, error_message = is_strong_password(password)
        if not is_valid:
            messages.error(request, error_message)
            protocol = SecurityProtocolDetail.objects.first()
            return render(request, 'createUsers.html', {
                'security_protocol': protocol,
                'email': email, 'first_name': first_name, 'last_name': last_name,
                'phone_number': phone_number, 'address': address, 'city': city,
                'state': state, 'country': country, 'zip_code': zip_code
            })

        try:
            role_id = int(role_id)  # Convert to integer

        except ValueError:
            messages.error(request, "Invalid Role ID")
            return render(request, 'createUsers.html', {'email': email, 'first_name': first_name, 'last_name': last_name, 'phone_number': phone_number, 'address': address, 'city': city, 'state': state, 'country': country, 'zip_code': zip_code})

        # Validate Admin Code for Admin or HelpDesk roles
        if role_id in [3, 4]:
            entered_admin_code = request.POST.get('admin_code', '').strip()
            expected_code = settings.ADMIN_ROLE_CREATION_CODE

            if entered_admin_code != expected_code:
                messages.error(request, "Invalid Admin Code.")
                protocol = SecurityProtocolDetail.objects.first()
                return render(request, 'createUsers.html', {
                    'security_protocol': protocol,
                    'email': email, 'first_name': first_name, 'last_name': last_name,
                    'phone_number': phone_number, 'address': address, 'city': city,
                    'state': state, 'country': country, 'zip_code': zip_code
                })
        status = request.POST.get('status', 'active')  # Default to 'active' if not provided

        # Create the user and save to the database
        user = LegacyUser(
            email=email,
            password=make_password(password), #hashed_password using Django's PBKDF2-SHA256 to hash it
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number,
            address=address,
            city=city,
            state=state,
            country=country,
            zip_code=zip_code,
            role_id=role_id,
            status=status
        )

        user.save()
        messages.success(request, f'User {email} created successfully')
        return redirect('create_user')  # Redirect after successful creation
    else:
        # Handle GET request by rendering a form page
        protocol = SecurityProtocolDetail.objects.first()
        return render(request, 'createUsers.html', {'security_protocol': protocol})


def handle_login(request):
    if request.method == "POST":
        if authenticate_user(request):  # Calls function from login.py
            return redirect('verify_otp')
        else:
            messages.error(request, "Invalid email or password.")
            return render(request, 'login.html')
    return render(request, 'login.html')


def verify_otp(request):
    if request.method == "POST":
        redirect_page = verify_otp_user(request)  # Calls function from verifyOTP.py

        if redirect_page == "expired":
            return render(request, 'verify_otp.html', {'otp_expired': True})
        
        elif redirect_page: 
            return redirect(redirect_page)
        else:
            messages.error(request, "Invalid OTP or your account is suspended.")
            return render(request, 'verify_otp.html')

    return render(request, 'verify_otp.html')  # Ensure it always returns an HttpResponse

def verify_otp_forgot(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        actual_otp = str(request.session.get('fp_otp'))
        timestamp = request.session.get('fp_otp_created_at')

        # Optional: expire OTP after 5 mins
        if timestamp and (datetime.now().timestamp() - timestamp > 300):
            messages.error(request, "OTP expired. Please request again.")
            return redirect('forgot_password')

        if entered_otp == actual_otp:
            return redirect('reset_password')  # New password form
        else:
            messages.error(request, "Incorrect OTP.")
            return render(request, 'verifyOTPForResetPassword.html')

    return render(request, 'verifyOTPForResetPassword.html')


from django.contrib.auth.hashers import make_password
import logging

def reset_password(request):
    email = request.session.get('fp_email')

    if request.method == 'POST':
        new_password1 = request.POST.get('new_password1')
        new_password2 = request.POST.get('new_password2')

        if new_password1 != new_password2:
            messages.error(request, "Passwords do not match.")
            return render(request, 'resetPassword.html')
        
        #  password strength validation 
        is_valid, error_message = is_strong_password(new_password1)
        if not is_valid:
            messages.error(request, error_message)
            return redirect('reset_password')

        try:
            user = User.objects.get(email=email)        
            # Hash the password
            hashed_password = make_password(new_password1)


            # Save the hashed password to the user
            user.password = hashed_password
            user.save()

            # Clear session OTP data
            request.session.pop('fp_email', None)
            request.session.pop('fp_otp', None)
            request.session.pop('fp_otp_created_at', None)

            messages.success(request, "Password reset successful.")
            return redirect('login')
        except User.DoesNotExist:
            messages.error(request, "Unexpected error. Please try again.")

    return render(request, 'resetPassword.html')




def custom_login(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        user = authenticate(request, username=email, password=password)
        if user is not None:
            try:
                # Check if the user's account is suspended
                account_status = UserAccountStatus.objects.get(email=email)
                if account_status.account_status == "Suspended":
                    messages.error(request, "Your account is under review and has been temporarily suspended")
                    return render(request, "login.html")
            except UserAccountStatus.DoesNotExist:
                pass

            # Generate an OTP and store it (along with the credentials) in the session
            otp = random.randint(100000, 999999)
            request.session['otp'] = otp
            request.session['email'] = email
            request.session['password'] = password
            print(f"Your OTP is: {otp}")  # For development/testing

            # Redirect to the OTP verification page
            return redirect('verify_otp')
        else:
            messages.error(request, "Invalid login credentials")
    return render(request, "login.html")



@login_required
@role_required(ROLE_CUSTOMER)
def customer_dashboard(request):
    user = request.user
    balance = user.wallet_balance  # or a default if None

    context = {
        'user_id' : user.pk,
        'email' : user.email,
        'first_name' : user.first_name,
        'last_name' : user.last_name,
        'phone_number' : user.phone_number,
        'address' : user.address,
        'city' : user.city,
        'state' : user.state,
        'country' : user.country,
        'zip_code' : user.zip_code,
        'wallet_balance': user.wallet_balance,
    }
    
    return render(request, 'customerUI.html', context)

@login_required
@role_required(ROLE_MERCHANT)
def merchant_dashboard(request):
    user = request.user  # Get the currently logged-in user
    status_filter = request.GET.get('status')  # <-- Get status from query param

    # Base queryset
    merchant_transactions = MerchantTransaction.objects.filter(merchant__user_id=user.user_id)

    # Apply filter only if status is selected
    if status_filter:
        merchant_transactions = merchant_transactions.filter(status=status_filter)

    # Calculate the total balance (sum of amount_sent)
    total_balance = merchant_transactions.filter(status='success').aggregate(Sum('amount_sent'))['amount_sent__sum'] or 0
    
    # Get count of successful transactions
    success_count = merchant_transactions.filter(status='success').count()

    # Get count of pending transactions
    pending_count = merchant_transactions.filter(status='pending').count()


    # Prepare the context with merchant information and filtered transactions
    context = {
        'user_id': user.pk,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'phone_number': user.phone_number,
        'address': user.address,
        'city': user.city,
        'state': user.state,
        'country': user.country,
        'zip_code': user.zip_code,
        'transactions': merchant_transactions,  # Add the filtered transactions to the context
        'total_balance': total_balance,  # Add total balance to the context
        'success_count': success_count,
        'pending_count': pending_count,
    }

    return render(request, 'merchantUI.html', context)

@login_required
@role_required(ROLE_HELPDESK)
def helpDesk_dashboard(request) :
    user = request.user #get currently logged in user

    context = {
        'user_id' : user.pk,
        'email' : user.email,
        'first_name' : user.first_name,
        'last_name' : user.last_name,
        'phone_number' : user.phone_number,
        'address' : user.address,
        'city' : user.city,
        'state' : user.state,
        'country' : user.country,
        'zip_code' : user.zip_code,
        #make sure user mode in model.py has these fields

    }
    return render(request, 'HelpDeskUI.html', context)

@login_required
@role_required(ROLE_ADMIN)
def systemAdmin_dashboard(request) :
    user = request.user #get currently logged in user

    context = {
        'user_id' : user.pk,
        'email' : user.email,
        'first_name' : user.first_name,
        'last_name' : user.last_name,
        'phone_number' : user.phone_number,
        'address' : user.address,
        'city' : user.city,
        'state' : user.state,
        'country' : user.country,
        'zip_code' : user.zip_code,
        #make sure user mode in model.py has these fields

    }
    return render(request, 'SysAdminUI.html', context)

@login_required
def change_passwordProfile(request):
    if request.method == "POST":
        current_password = request.POST.get("current_password")
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")

        user = request.user

        if not check_password(current_password, user.password):
            messages.error(request, "Current password is incorrect.")
            return redirect('change_passwordProfile')

        if new_password != confirm_password:
            messages.error(request, "New password and confirm password do not match.")
            return redirect('change_passwordProfile')
        
        # Check if new password is same as current password
        if check_password(new_password, user.password):
            messages.error(request, "New password must be different from the current password.")
            return redirect('change_passwordProfile')
        
        #  password strength validation 
        is_valid, error_message = is_strong_password(new_password)
        if not is_valid:
            messages.error(request, error_message)
            return redirect('change_passwordProfile')

        # If good, save new password
        user.password = make_password(new_password)
        user.save()

        update_session_auth_hash(request, user)

        messages.success(request, "Password changed successfully.")

        # Role-based redirect name
        role_redirects = {
            1: 'customer_profile',
            2: 'merchant_profile',
            3: 'sysadmin_dashboard',
            4: 'helpdesk_profile'
        }

        url_name = role_redirects.get(user.role_id, 'home')
        resolved_url = reverse(url_name)  # this returns e.g. "/customer/profile/"

        return render(request, 'changePasswordFromProfile.html', {
            'redirect_url': resolved_url
        })

    # For GET requests, you can still pass the redirect link
    role_redirects = {
        1: 'customer_profile',
        2: 'merchant_profile',
        3: 'sysadmin_dashboard',
        4: 'helpdesk_profile'
    }
    url_name = role_redirects.get(request.user.role_id, 'home')
    resolved_url = reverse(url_name)

    return render(request, 'changePasswordFromProfile.html', {
        'redirect_url': resolved_url
    })

def sysadmin_settings(request):
    protocol = SecurityProtocolDetail.objects.first()
    content = protocol.content if protocol and protocol.content else 'No security content saved yet.'
    return render(request, 'SysAdminSecuritySettings.html', {
        'protocol_content': content,
    })

def update_security_protocol_text(request):
    if request.method == 'POST':
        new_content = request.POST.get('security_content')
        protocol = SecurityProtocolDetail.objects.first()
        if protocol:
            protocol.content = new_content
            protocol.save()
        else:
            SecurityProtocolDetail.objects.create(content=new_content)
        messages.success(request, "Security protocol details updated successfully.")
    return redirect('sysadmin_settings')

def process_payment(request):
    # Placeholder logic; replace with your actual payment processing code.
    return render(request, 'process_payment.html')

def transaction_status(request, transaction_id):
    # Retrieve the transaction with the given transaction_id
    transaction = get_object_or_404(Transaction, transaction_id=transaction_id)
    return render(request, 'transaction_status.html', {'transaction': transaction})

def user_transactions(request):
    # Ensure the user is authenticated (you can add @login_required decorator if needed)
    transactions = Transaction.objects.filter(user=request.user)
    return render(request, 'user_transactions.html', {'transactions': transactions})

def custom_logout(request):
    # Django will handle session clearing automatically when calling logout()
    logout(request)
    return redirect('login')  # Redirect to login page after logout


# Customer

@login_required
def customer_profile(request) :
    user = request.user #get currently logged in user

    context = {
        'user_id' : user.pk,
        'email' : user.email,
        'first_name' : user.first_name,
        'last_name' : user.last_name,
        'phone_number' : user.phone_number,
        'address' : user.address,
        'city' : user.city,
        'state' : user.state,
        'country' : user.country,
        'zip_code' : user.zip_code,
        #make sure user mode in model.py has these fields

    }
    return render(request, 'CustomerProfile.html', context)

@login_required
def top_up_wallet(request):
    if request.method == 'POST':
        top_up_amount = request.POST.get('top_up_amount', 0)
        user = request.user  # This is your LegacyUser
        user.wallet_balance += Decimal(top_up_amount)
        user.save(update_fields=['wallet_balance'])
        messages.success(request, f"Successfully topped up your wallet by ${top_up_amount}!")
        return redirect('customer_dashboard')
    else:
        return render(request, 'topUpWallet.html')



@login_required
def view_purchase(request):
    # Filter by the logged-in customer's email
    user_email = request.user.email
    # Get all rows in merchant_transactions for this customer's email
    purchases = MerchantTransaction.objects.filter(customer_email=user_email)

    return render(request, 'viewPurchaseUI.html', {'transactions': purchases})

def customer_ui(request):
    return render(request, 'customerUI.html')

def contact_support(request):
    return render(request, 'contact.html')

# Merchant

@login_required
def merchant_profile(request) :
    user = request.user #get currently logged in user

    context = {
        'user_id' : user.pk,
        'email' : user.email,
        'first_name' : user.first_name,
        'last_name' : user.last_name,
        'phone_number' : user.phone_number,
        'address' : user.address,
        'city' : user.city,
        'state' : user.state,
        'country' : user.country,
        'zip_code' : user.zip_code,
        #make sure user mode in model.py has these fields

    }
    return render(request, 'MerchantProfile.html', context)

def merchant_transactions_view(request):
    transactions = MerchantTransaction.objects.all()  # Fetch all transactions
    return render(request, 'transactions.html', {'transactions': transactions})

def is_valid_card(card_number):
    """ Validate credit card number using Luhn Algorithm """
    card_number = card_number.replace(" ", "")  # Remove spaces

    if not card_number.isdigit() or len(card_number) not in [13, 15, 16]:
        return False

    total = 0
    reverse_digits = card_number[::-1]

    for i, digit in enumerate(reverse_digits):
        num = int(digit)
        if i % 2 == 1:
            num *= 2
            if num > 9:
                num -= 9
        total += num

    return total % 10 == 0

def is_expired(expiry_date):
    """ Check if the expiry date is in the future (MM/YY format) """
    try:
        exp_month, exp_year = map(int, expiry_date.split("/"))
        exp_year += 2000  # Convert YY to YYYY
        return datetime.date(exp_year, exp_month, 1) < datetime.date.today()
    except:
        return True  # If format is wrong, consider it expired

@login_required
def process_money_transfer(request):
    if request.method == 'POST':
        merchant_email = request.POST.get('merchant_email')
        amount_str = request.POST.get('amount')
        payment_method = request.POST.get('payment_method')
        saved_card_id = request.POST.get('saved_card_id')
        expiry_date = request.POST.get('expiry_date', '')
        save_payment_method = request.POST.get('save_payment_method') == 'on'

        card_number = ''
        if saved_card_id:
            try:
                saved_card = SavedPaymentMethod.objects.get(id=saved_card_id, user=request.user)
                vault_entry = TokenVault.objects.get(token=saved_card.token)
                card_number = vault_entry.get_card_number()
                payment_method = saved_card.payment_type  
            except Exception:
                messages.error(request, "Failed to retrieve saved card.")
                return redirect('customer_dashboard')
        else:
            card_number = request.POST.get('card_number', '')

        # Validate card number using Luhn algorithm
        if not is_valid_card(card_number):
            messages.error(request, "Invalid card number.")
            return redirect('customer_dashboard')
        
        if not match_card_brand(card_number, payment_method):
            messages.error(request, f"The card number does not match the selected {payment_method} format.")
            return redirect('customer_dashboard')


        # Check expiry format and expiration
        import re
        if not re.match(r'^\d{2}/\d{2}$', expiry_date):
            messages.error(request, "Invalid expiry date format.")
            return redirect('customer_dashboard')
        if is_expired(expiry_date):
            messages.error(request, "Card is expired.")
            return redirect('customer_dashboard')

        # Validate amount
        try:
            amount = Decimal(amount_str)
            if amount <= 0:
                raise ValueError
        except Exception:
            messages.error(request, "Invalid amount.")
            return redirect('customer_dashboard')

        # Get merchant user by email
        merchant = get_object_or_404(LegacyUser, email=merchant_email, role_id=2)
        transaction_number = str(uuid.uuid4()).replace('-', '')[:12]
        user = request.user

        # Create transaction + save card if needed
        with db_transaction.atomic():
            transaction = MerchantTransaction.objects.create(
                merchant=merchant,
                customer_email=user.email,
                customer_first_name=user.first_name,
                customer_last_name=user.last_name,
                transaction_number=transaction_number,
                amount_sent=amount,
                payment_method=payment_method,
                phone_number=user.phone_number,
                address=user.address,
                city=user.city,
                state=user.state,
                country=user.country,
                status='pending'
            )

            # New Save Card Logic (No duplicate save)
            if save_payment_method and payment_method in ['VISA', 'MASTERCARD'] and not saved_card_id:
                try:
                    existing_methods = SavedPaymentMethod.objects.filter(user=request.user)

                    for method in existing_methods:
                        vault_entry = TokenVault.objects.get(token=method.token)
                        existing_card_number = vault_entry.get_card_number()
                        if existing_card_number == card_number:
                            logger.info("Card already saved. Skipping save.")
                            messages.info(request, "This card is already saved.")
                            break
                    else:
                        # No duplicate, so save
                        token = f"tok_{uuid.uuid4().hex}"
                        TokenVault.create_entry(token=token, card_number=card_number)

                        SavedPaymentMethod.objects.create(
                            user=request.user,
                            payment_type=payment_method,
                            last_four_digits=card_number[-4:],
                            token=token
                        )
                except Exception as e:
                    logger.error(f"Failed to save payment method: {str(e)}")
        # Launch async processing
        print(f"DEBUG: Starting thread for transaction {transaction.id}", flush=True)
        thread = threading.Thread(target=process_payment_delayed, args=(transaction.id, amount, card_number))
        thread.start()

        return redirect('view_purchase')



def match_card_brand(card_number, brand):
    card_number = card_number.replace(" ", "")
    if brand == "VISA":
        # VISA starts with 4 and is 16 in length
        return bool(re.match(r"^4\d{15}$", card_number))
    elif brand == "MASTERCARD":
        # MasterCard starts with 51-55 or 2221-2720 and is 16 in length
        return bool(re.match(r"^(5[1-5]\d{14}|2(2[2-9]\d{13}|[3-6]\d{14}|7[01]\d{13}|720\d{13}))$", card_number))
    else:
        return False




@login_required
def get_saved_payment_methods(request):
    methods = SavedPaymentMethod.objects.filter(user=request.user).values(
        'id',
        'payment_type',
        'last_four_digits'
    )
    
    formatted_methods = []
    for method in methods:
        formatted_methods.append({
            'id': method['id'],
            'display': f"{method['payment_type']} ending in {method['last_four_digits']}"
        })
    
    return JsonResponse({'methods': formatted_methods})

@login_required
def get_saved_card_detail(request, card_id):
    try:
        saved_card = SavedPaymentMethod.objects.get(id=card_id, user=request.user)
        token = saved_card.token
        vault_entry = TokenVault.objects.get(token=token)
        card_number = vault_entry.get_card_number()

        return JsonResponse({
            'masked_number': f"************{card_number[-4:]}",
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)




# Bank Authorization
def process_payment_delayed(transaction_id, amount, card_number):
    """
    Simulated delayed payment processing function.
    The status is updated after 10 seconds.
    """
    print(f"Starting payment delay for transaction {transaction_id}", flush=True)  # Debugging log
    time.sleep(20)  # Simulate processing delay

    try:
        # Retrieve the transaction from the database
        transaction = MerchantTransaction.objects.get(id=transaction_id)
        print(f"Processing transaction {transaction.transaction_number}", flush=True)  # Debugging log
        
        max_retries = 2
        retry_delay = 5  # seconds between retries
        attempt = 0
        success = False

        while attempt < max_retries and not success:
            print(f"Attempt {attempt + 1} to capture payment...")
            time.sleep(retry_delay)

            transaction = MerchantTransaction.objects.get(id=transaction_id)

            # Simulate 50% chance of success
            if random.random() < 0.5:
                transaction.status = 'success'
                transaction.save()
                print("Payment captured successfully.")
                success = True            
                send_mail(
                    subject='Payment Received from SafePay',
                    message=(
                        f"Hi {transaction.merchant.first_name},\n\n"
                        f"You've received a payment of ${transaction.amount_sent} from "
                        f"{transaction.customer_first_name} {transaction.customer_last_name}.\n"
                        f"Transaction ID: {transaction.transaction_number}\n\n"
                        f"Please fulfill the order as soon as possible.\n\n"
                        f"– SafePay Gateway"
                    ),
                    from_email=None,  # uses DEFAULT_FROM_EMAIL
                    recipient_list=['testmerchantt1212@gmail.com'],
                    fail_silently=False
                )
            else:
                attempt += 1
                if attempt < max_retries:
                    print("Payment failed. Retrying...")
                else:
                    transaction.status = 'failed'
                    transaction.save()
                    print("All payment attempts failed.")
            print(f"Transaction {transaction.transaction_number} updated to {transaction.status}")

    except MerchantTransaction.DoesNotExist:
        print(f"Transaction {transaction_id} does not exist.")     

@login_required
def complaints_view(request):
    # Get the complaints related to the logged-in user
    complaints = Complaint.objects.filter(user=request.user)
    
    # Get a list of user emails, excluding the current user's email
    user_emails = LegacyUser.objects.exclude(email=request.user.email).values_list('email', flat=True)
    
    # Pass the complaints and emails to the template
    context = {
        'complaints': complaints,
        'user_email': request.user.email,
        'user_emails': user_emails,
    }
    
    return render(request, 'complaints.html', context)



# Admin
@login_required
def sysadmin_view_transactions(request):
    # Retrieve all purchase transactions (latest first)
    transactions = MerchantTransaction.objects.all().order_by('-created_at')
    return render(request, 'SysAdminViewTransaction.html', {'transactions': transactions})


def sysadmin_settings(request):
    return render(request, 'SysAdminSecuritySettings.html')

def sysadmin_view_user_logs(request):
    # any context you want to pass in
    return render(request, 'SysAdminViewUserLogs.html')

@login_required
def submit_complaint(request):
    if request.method == 'POST':
        form = ComplaintForm(request.POST)
        if form.is_valid():
            # Set the complainant (user) to the logged-in user
            complaint = form.save(commit=False)
            complaint.user = request.user  # Automatically set the logged-in user as the complainant
            complaint.save()

            messages.success(request, "Complaint submitted successfully.")
            return redirect('complaints_view')  # Or wherever you want to redirect after success
    else:
        form = ComplaintForm()

    return render(request, 'complaints.html', {'form': form})

@login_required
def view_submitted_complaints(request):
    role_id = request.user.role_id  
    # Fetch complaints for the currently logged-in user
    complaints = Complaint.objects.filter(user=request.user)
    
    return render(request, 'viewSubmittedComplaints.html', {'role_id': role_id, 'complaints': complaints})

@login_required
def update_security_protocols(request):
    if request.method == 'POST':
        protocol_name = request.POST.get('protocol_name')
        protocol_version = request.POST.get('protocol_version')
        protocol_description = request.POST.get('protocol_description')

        # Save or update security protocols
        SecurityProtocol.objects.update_or_create(
            name=protocol_name,
            defaults={
                'version': protocol_version,
                'description': protocol_description,
            }
        )
        # Setup success message
        messages.success(request, 'Security protocol updated successfully.')
        return redirect('sysadmin_settings')

    else:
        return redirect('sysadmin_settings')


@login_required
def view_tickets(request):
    current_user = request.user.role_id

    complaints = Complaint.objects.exclude(user=current_user)

    context = {
        'current_user': current_user,
        'complaints': complaints
    }

    return render(request, 'tickets.html', context)


@login_required
def ticket_details(request, ticket_id):
    # Fetch the ticket from the database
    ticket = get_object_or_404(Complaint, id=ticket_id)

    if request.method == 'POST':
        # Handle form submission
        form = TicketUpdateForm(request.POST, instance=ticket)
        if form.is_valid():
            form.save()
            return redirect('ticket_details.html', ticket_id=ticket.id)
    else:
        # Display the form with the current ticket data
        form = TicketUpdateForm(instance=ticket)

    context = {
        'ticket': ticket,
        'form': form,
    }

    return render(request, 'ticket_details.html', context)

def helpdesk_profile(request) :
    user = request.user #get currently logged in user

    context = {
        'user_id' : user.pk,
        'email' : user.email,
        'first_name' : user.first_name,
        'last_name' : user.last_name,
        'phone_number' : user.phone_number,
        'address' : user.address,
        'city' : user.city,
        'state' : user.state,
        'country' : user.country,
        'zip_code' : user.zip_code,
        #make sure user mode in model.py has these fields

    }
    return render(request, 'HelpdeskProfile.html', context)


@login_required
def live_chat(request):
    return render(request, 'HelpDeskUI.html')

@login_required
def helpdesk_settings(request):
    return render(request, 'HelpdeskSettings.html')

@login_required
def suspend_customer(request):
    if request.method == 'POST':
        transaction_id = request.POST.get('transaction_id')
        transaction = get_object_or_404(MerchantTransaction, id=transaction_id)
        customer_email = transaction.customer_email

        # Check if the customer is already suspended
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT account_status FROM user_account_status WHERE email = %s",
                [customer_email]
            )

            row = cursor.fetchone()
            if row and row[0] == 'Suspended':
                return JsonResponse({'status': 'error', 'message': 'The user has already been suspended.'})


            # If not suspended, proceed to suspend the customer
            cursor.execute(
                "UPDATE user_account_status SET account_status = 'Suspended' WHERE email = %s",
                [customer_email]

            )

        return JsonResponse({'status': 'success', 'message': 'Customer suspended successfully.'})

    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})



@login_required

def sysadmin_manage_users(request):
    user_statuses = UserAccountStatus.objects.all()
    return render(request, 'SysAdminManageStatus.html', {'user_statuses': user_statuses})



@csrf_exempt
@login_required
def update_user_status(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        new_status = request.POST.get('status')

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE user_account_status SET account_status = %s WHERE email = %s",
                    [new_status, email]
                )
            return JsonResponse({'status': 'success', 'message': 'Status updated successfully.'})

        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})
    

@login_required
def test(request):
    return render(request, 'Something.html')

@login_required
@require_POST
def delete_saved_card(request, card_id):
    try:
        card = SavedPaymentMethod.objects.get(id=card_id, user=request.user)
        card.delete()
        return JsonResponse({'status': 'success'})
    except SavedPaymentMethod.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Card not found'}, status=404)