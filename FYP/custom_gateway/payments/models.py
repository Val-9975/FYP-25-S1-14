from django.db import models
from django.conf import settings

class Transaction(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,  # This will refer to LegacyUser once set in settings.py
        on_delete=models.CASCADE
    )
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    card_number = models.CharField(max_length=16)
    transaction_id = models.CharField(max_length=12, unique=True)
    status = models.CharField(
        max_length=10,
        choices=[('success', 'Success'), ('failed', 'Failed')]
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.transaction_id

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

    class Meta:
        db_table = 'merchant_transactions'