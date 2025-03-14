from django import forms

class PaymentForm(forms.Form):
    card_number = forms.CharField(max_length=16, label='Card Number')
    amount = forms.DecimalField(max_digits=10, decimal_places=2, label='Amount')
