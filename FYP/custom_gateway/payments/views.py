import uuid
import threading
import time
import random
import datetime
from django.shortcuts import render
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from .models import MerchantTransaction, LegacyUser, Transaction, Complaint
from django.db.models import Sum
from .login import authenticate_user
from .verifyOTP import verify_otp_user
from .logout import custom_logout
from .forms import ComplaintForm

def create_user(request):
    if request.method == 'POST':
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
        
        try:
            role_id = int(role_id)  # Convert to integer
        except ValueError:
            messages.error(request, "Invalid Role ID")
            return render(request, 'createUsers.html', {'email': email, 'first_name': first_name, 'last_name': last_name, 'phone_number': phone_number, 'address': address, 'city': city, 'state': state, 'country': country, 'zip_code': zip_code})

        status = request.POST.get('status', 'active')  # Default to 'active' if not provided

        # Hash the password before saving (not hashing for now, if not cannot see in database)
        #hashed_password = make_password(password)

        # Create the user and save to the database
        user = LegacyUser(
            email=email,
            password=password, #hashed_password to hash it
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

    return render(request, 'createUsers.html')

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
        redirect_page = verify_otp_user(request)  # Calls function from verify.py
        if redirect_page:
            return redirect(redirect_page)
        else:
            messages.error(request, "Invalid OTP. Please try again.")
            return render(request, 'verify_otp.html')

    return render(request, 'verify_otp.html')

@login_required
def customer_dashboard(request):
    user = request.user

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
    }
    
    return render(request, 'customerUI.html', context)

@login_required
def merchant_dashboard(request):
    user = request.user  # Get the currently logged-in user

    # merchant_transactions = MerchantTransaction.objects.filter(merchant__user_id=user.user_id)

    # Get the 'status' filter from the URL query parameters
    status_filter = request.GET.get('status', None)

    # Use the helper function to get the filtered transactions
    transactions = filter_transactions(user, status_filter)

    # Calculate the total balance (sum of amount_sent) for successful transactions
    total_balance = transactions.filter(status='success').aggregate(Sum('amount_sent'))['amount_sent__sum'] or 0
    
    # Get count of transactions by status
    success_count = transactions.filter(status='success').count()
    pending_count = transactions.filter(status='pending').count()
    failed_count = transactions.filter(status='failed').count()
    

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
        'transactions': transactions,  # Add the filtered transactions to the context
        'total_balance': total_balance,  # Add total balance to the context
        'success_count': success_count,
        'pending_count': pending_count,
    }

    return render(request, 'merchantUI.html', context)

def filter_transactions(user, status_filter=None):
    # Fetch all transactions for the logged-in merchant
    merchant_transactions = MerchantTransaction.objects.filter(merchant__user_id=user.user_id)

    # Apply status filter if provided
    if status_filter:
        transactions = merchant_transactions.filter(status=status_filter)
    else:
        transactions = merchant_transactions  # Return all transactions if no filter is applied

    return transactions

def luhn_check(card_number):
    """ Validate card number using Luhn Algorithm """
    digits = [int(d) for d in card_number[::-1]]
    checksum = sum(digits[0::2]) + sum(sum(divmod(2 * d, 10)) for d in digits[1::2])
    return checksum % 10 == 0

def is_expired(expiry_date):
    """ Check if the expiry date is in the future (MM/YY format) """
    try:
        exp_month, exp_year = map(int, expiry_date.split("/"))
        exp_year += 2000  # Convert YY to YYYY
        return datetime.date(exp_year, exp_month, 1) < datetime.date.today()
    except:
        return True  # If format is wrong, consider it expired

@login_required
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

@login_required
def process_money_transfer(request):
    if request.method == 'POST':
        merchant_email = request.POST.get('merchant_email')
        amount = request.POST.get('amount')
        payment_method = request.POST.get('payment_method')
        card_number = request.POST.get('card_number', '')

        # Look up the merchant
        merchant = get_object_or_404(LegacyUser, email=merchant_email, role_id=2)
        
        if not is_valid_card(card_number):
            messages.error(request, "Invalid credit card number.")
            return redirect('customer_dashboard')

        # Generate a unique transaction number
        transaction_number = str(uuid.uuid4()).replace('-', '')[:12]

        # Assume the payment is "Pending" initially
        transaction = MerchantTransaction.objects.create(
            merchant=merchant,
            customer_email=request.user.email,
            customer_first_name=request.user.first_name,
            customer_last_name=request.user.last_name,
            transaction_number=transaction_number,
            amount_sent=amount,
            payment_method=payment_method,
            phone_number=request.user.phone_number,
            address=request.user.address,
            city=request.user.city,
            state=request.user.state,
            country=request.user.country,
            status='pending'
        )

        thread = threading.Thread(target=process_payment_delayed, args=(transaction.id, amount, card_number))
        thread.start()

        transaction.save()

        return redirect('view_purchase')
    else:
        return redirect('customer_dashboard')


def process_payment_delayed(transaction_id, amount, card_number):
    """
    Simulated delayed payment processing function.
    The status is updated after 10 seconds.
    """
    time.sleep(20)  # Simulate processing delay

    try:
        # Retrieve the transaction from the database
        transaction = MerchantTransaction.objects.get(id=transaction_id)

        # Simulate payment success (replace with real logic)
        transaction.status = 'success' if float(transaction.amount_sent) > 0 else 'failed'

        # Save the updated status
        transaction.save()
        print(f"Transaction {transaction.transaction_number} updated to {transaction.status}")

    except MerchantTransaction.DoesNotExist:
        print(f"Transaction {transaction_id} does not exist.")

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
    return redirect('handle_login')  # Redirect to login page after logout


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

def merchant_transactions_view(request):
    transactions = MerchantTransaction.objects.all()  # Fetch all transactions
    return render(request, 'transactions.html', {'transactions': transactions})

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