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

    # Fetch the merchant's transactions using the user's email (customer_email in the transaction model)
    merchant_transactions = MerchantTransaction.objects.filter(customer_email=user.email)

    # Calculate the total balance (sum of amount_sent)
    total_balance = merchant_transactions.aggregate(Sum('amount_sent'))['amount_sent__sum'] or 0

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
        # Retrieve data from the form
        merchant_email = request.POST.get('merchant_email')
        amount = request.POST.get('amount')
        #currency = request.POST.get('currency')
        payment_method = request.POST.get('payment_method')
        card_number = request.POST.get('card_number', '')

        # Look up the merchant using the provided email and ensure they are a merchant (role_id = 2)
        merchant = get_object_or_404(LegacyUser, email=merchant_email, role_id=2)

        # Generate a unique transaction number (e.g., a 12-character string)
        transaction_number = str(uuid.uuid4()).replace('-', '')[:12]

        # Create the MerchantTransaction record using the logged-in customer's details
        MerchantTransaction.objects.create(
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
            country=request.user.country
        )

        # Redirect to a success page or purchase view after processing
        return redirect('view_purchase')
    else:
        return redirect('customer_dashboard')

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