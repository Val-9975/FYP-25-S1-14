from django import forms
from .models import Complaint, LegacyUser

class PaymentForm(forms.Form):
    card_number = forms.CharField(max_length=16, label='Card Number')
    amount = forms.DecimalField(max_digits=10, decimal_places=2, label='Amount')

class ComplaintForm(forms.ModelForm):
    class Meta:
        model = Complaint
        fields = ['complained_against', 'category', 'complaint_text']

    complained_against = forms.ModelChoiceField(queryset=LegacyUser.objects.all(), to_field_name="email")  # Allow selection by email
    category = forms.ChoiceField(choices=Complaint.CATEGORY_CHOICES)
    complaint_text = forms.CharField(widget=forms.Textarea, max_length=200)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Optionally, set a default selection or filtering options based on user email or some other condition
        self.fields['complained_against'].queryset = LegacyUser.objects.all()  # Ensure we show all users


class TicketUpdateForm(forms.ModelForm):
    class Meta:
        model = Complaint
        fields = ['status', 'comments']

    STATUS_CHOICES = [
        ('Open', 'Open'),
        ('Closed', 'Closed'),
    ]
    status = forms.ChoiceField(choices=STATUS_CHOICES, widget=forms.Select(attrs={'class': 'form-select'}))
    comments = forms.CharField(widget=forms.Textarea(attrs={'class': 'form-textarea', 'rows': 4}))