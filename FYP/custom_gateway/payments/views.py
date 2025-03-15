import uuid
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

    merchant_transactions = MerchantTransaction.objects.filter(merchant__user_id=user.user_id)

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

        # Simulate payment processing (You can integrate an actual payment gateway here)
        payment_success = process_payment_mock(amount, card_number)

        # Update status based on payment result
        if payment_success:
            transaction.status = 'success'
        else:
            transaction.status = 'failed'

        transaction.save()

        return redirect('view_purchase')
    else:
        return redirect('customer_dashboard')


def process_payment_mock(amount, card_number):
    """
    Simulated payment processing function.
    Returns True for success and False for failure.
    """
    if card_number and len(card_number) == 16 and float(amount) > 0:
        return True  # Payment success
    return False  # Payment failed


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
    return render(request, 'contact.html')

def merchant_transactions_view(request):
    transactions = MerchantTransaction.objects.all()  # Fetch all transactions
    return render(request, 'transactions.html', {'transactions': transactions})