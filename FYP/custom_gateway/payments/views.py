import uuid
import threading
import time
import random
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Sum
from .models import MerchantTransaction, LegacyUser, Transaction
from .login import handle_login
from .logout import custom_logout

def custom_login(request):
    response = handle_login(request)  # Call login function

    if response is None:  # Ensure a valid response is returned
        return render(request, 'login.html')  

    return response  # Return the response from handle_login

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

@login_required
def process_money_transfer(request):
    if request.method == 'POST':
        merchant_email = request.POST.get('merchant_email')
        amount = request.POST.get('amount')
        payment_method = request.POST.get('payment_method')
        card_number = request.POST.get('card_number', '')

        # Look up the merchant
        merchant = get_object_or_404(LegacyUser, email=merchant_email, role_id=2)

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
    return redirect('login')  # Redirect to login page after logout


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
    user = request.user

    # Check how you differentiate merchants from customers
    if hasattr(user, 'role_id') and user.role_id == 2:
        dashboard_url = 'merchant_dashboard'
    else:
        dashboard_url = 'customer_dashboard'

    return render(request, 'contact.html', {'dashboard_url': dashboard_url})

def merchant_transactions_view(request):
    transactions = MerchantTransaction.objects.all()  # Fetch all transactions
    return render(request, 'transactions.html', {'transactions': transactions})