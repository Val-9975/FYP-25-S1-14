import uuid
import threading
import time
import logging
import random
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
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
from .models import SecurityProtocol
from django.http import JsonResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from .login import authenticate_user
from .verifyOTP import verify_otp_user
logger = logging.getLogger(__name__)


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
    else:
        # Handle GET request by rendering a form page
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
        redirect_page = verify_otp_user(request)  # Calls function from verifyOTP.py
        if redirect_page:
            return redirect(redirect_page)
        else:
            messages.error(request, "Invalid OTP or your account is suspended.")
            return render(request, 'verify_otp.html')

    return render(request, 'verify_otp.html')  # Ensure it always returns an HttpResponse




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
    return redirect('login')  # Redirect to login page after logout


# Customer

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
def merchant_transactions_view(request):
    transactions = MerchantTransaction.objects.all()  # Fetch all transactions
    return render(request, 'transactions.html', {'transactions': transactions})

@login_required
def process_money_transfer(request):
    if request.method == 'POST':
        merchant_email = request.POST.get('merchant_email')
        amount_str = request.POST.get('amount')
        payment_method = request.POST.get('payment_method')
        card_number = request.POST.get('card_number', '')

        try:
            amount = Decimal(amount_str)
        except Exception:
            messages.error(request, "Invalid amount.")
            return redirect('customer_dashboard')

        merchant = get_object_or_404(LegacyUser, email=merchant_email, role_id=2)
        token = f"tok_{uuid.uuid4().hex}"
        transaction_number = str(uuid.uuid4()).replace('-', '')[:12]
        user = request.user

        with db_transaction.atomic():
            # Create transaction entries
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

            Transaction.objects.create(
                user=user,
                amount=amount,
                token=token,
                transaction_id=transaction_number,
                status='success'
            )

            TokenVault.create_entry(token=token, card_number=card_number)

        # Start the delayed payment status update thread
        print(f"DEBUG: Starting thread for transaction {transaction.id}", flush=True)
        thread = threading.Thread(target=process_payment_delayed, args=(transaction.id, amount, card_number))
        thread.start()

        return redirect('view_purchase')


    if payment_method.upper() == "SAFEPAY WALLET":
        if user.wallet_balance < amount:
            # Create transaction with failed status
            transaction_number = str(uuid.uuid4()).replace('-', '')[:12]
            MerchantTransaction.objects.create(
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
                status='failed'
            )
            messages.error(request, "Insufficient wallet balance. Transaction failed.")
            return redirect('view_purchase')
        else:
            user.wallet_balance -= amount
            user.save(update_fields=['wallet_balance'])

    # Move this outside of the SAFEPAY WALLET check so it's always executed
    transaction_number = str(uuid.uuid4()).replace('-', '')[:12]
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

    thread = threading.Thread(target=process_payment_delayed, args=(transaction.id, amount, card_number))
    thread.start()

    return redirect('view_purchase')

        

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


@login_required
def live_chat(request):
    return render(request, 'HelpDeskUI.html')

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
    
