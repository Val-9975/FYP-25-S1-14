from django.db import models
from django.conf import settings
from cryptography.fernet import Fernet
from django.utils.functional import cached_property
from django.contrib.auth.models import User
import uuid

class Transaction(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,  # This will refer to LegacyUser once set in settings.py
        on_delete=models.CASCADE
    )
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    card_number = models.CharField(max_length=16)
    transaction_id = models.CharField(max_length=12, unique=True)
    token = models.CharField(max_length=255, null=True, blank=True)
    status = models.CharField(
        max_length=10,
        choices=[('success', 'Success'), ('failed', 'Failed')]
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.transaction_id

class TokenVault(models.Model):
    token = models.CharField(max_length=36, unique=True)  # Matches Transaction.token
    encrypted_card_number = models.CharField(max_length=255)  # Encrypted card number
    created_at = models.DateTimeField(auto_now_add=True)

    @classmethod
    def create_entry(cls, token, card_number):
        """Encrypt card number and save to vault."""
        encrypted_card = fernet.encrypt(card_number.encode()).decode()
        return cls.objects.create(token=token, encrypted_card_number=encrypted_card)

    def get_card_number(self):
        """Decrypt card number (for authorized use only)."""
        return fernet.decrypt(self.encrypted_card_number.encode()).decode()

    class Meta:
        db_table = 'payments_tokenvault'

class LegacyUser(models.Model):
    user_id = models.AutoField(primary_key=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    phone_number = models.CharField(max_length=20, null=True, blank=True)
    address = models.CharField(max_length=255, null=True, blank=True)
    city = models.CharField(max_length=50, null=True, blank=True)
    state = models.CharField(max_length=50, null=True, blank=True)
    country = models.CharField(max_length=50, null=True, blank=True)
    zip_code = models.CharField(max_length=20, null=True, blank=True)
    role_id = models.IntegerField()
    status = models.CharField(max_length=20, default='active')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    wallet_balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    class Meta:
        db_table = 'users'  # Map to your existing table
        managed = False     # Don't let Django manage this table

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []  # No additional fields required during user creation

    def __str__(self):
        return self.email

    @property
    def is_active(self):
        return self.status == 'active'

    @property
    def is_authenticated(self):
        # Always return True for a valid user instance
        return True

    @property
    def is_anonymous(self):
        # Authenticated users are not anonymous.
        return False

class MerchantTransaction(models.Model):
    id = models.AutoField(primary_key=True)
    merchant = models.ForeignKey(
        LegacyUser,
        on_delete=models.CASCADE,
        limit_choices_to={'role_id': 2}  # ensures only merchants are selectable
    )
    STATUS_CHOICES = [
    ('pending', 'Pending'),
    ('success', 'Success'),
    ('failed', 'Failed'),
    ]
    customer_email = models.EmailField()
    customer_first_name = models.CharField(max_length=50)
    customer_last_name = models.CharField(max_length=50)
    transaction_number = models.CharField(max_length=50)
    amount_sent = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=50)
    phone_number = models.CharField(max_length=20, null=True, blank=True)
    address = models.CharField(max_length=255, null=True, blank=True)
    city = models.CharField(max_length=50, null=True, blank=True)
    state = models.CharField(max_length=50, null=True, blank=True)
    country = models.CharField(max_length=50, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    # token = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = 'merchant_transactions'

class Complaint(models.Model):
    CATEGORY_CHOICES = [
        ('Poor Service', 'Poor Service'),
        ('Account Issue', 'Account Issue'),
        ('Fraud', 'Fraud'),
        ('Monetary Issue', 'Monetary Issue'),
    ]
    
    user = models.ForeignKey(LegacyUser, on_delete=models.CASCADE, related_name="complaints", null=True, blank=True)  # The user filing the complaint
    complained_against = models.ForeignKey(LegacyUser, on_delete=models.CASCADE, related_name='complaints_against')
    complaint_text = models.TextField(max_length=200)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        # Ensure the string returns the emails of the complainant and the user being complained about
        return f"Complaint by {self.user.email} against {self.complained_against.email}"
    
    class Meta:
        db_table = 'users_complaints'
        
class SecurityProtocol(models.Model):
    name = models.CharField(max_length=255, unique=True)
    version = models.CharField(max_length=50)
    description = models.TextField()
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        managed = False  
        db_table = 'security_protocol'

    def __str__(self):
        return f"{self.name} (v{self.version})"
    
class UserAccountStatus(models.Model):
    email = models.EmailField(primary_key=True)
    password = models.CharField(max_length=255)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    phone_number = models.CharField(max_length=20, null=True, blank=True)
    address = models.CharField(max_length=255, null=True, blank=True)
    city = models.CharField(max_length=50, null=True, blank=True)
    state = models.CharField(max_length=50, null=True, blank=True)
    country = models.CharField(max_length=50, null=True, blank=True)
    zip_code = models.CharField(max_length=20, null=True, blank=True)
    role_id = models.IntegerField()
    account_status = models.CharField(max_length=20, default='Available')

    class Meta:
        db_table = 'user_account_status'
        managed = False  