from django.db import models
import uuid

# Base abstract class
class BaseClass(models.Model):
    UID = models.UUIDField(default=uuid.uuid4, primary_key=True, null=False, blank=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

class Users(BaseClass):
    email = models.EmailField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    otp = models.IntegerField(default=654321)
    forgot_password_otp = models.IntegerField(default=654321)
    is_active = models.BooleanField(default=False)

    def __str__(self):
        return f"User: {self.email} | Active: {'Yes' if self.is_active else 'No'}"

    def is_verified(self):
        return self.is_active

class UserDetails(BaseClass):
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=100)
    dob = models.DateField()
    gender = models.CharField(max_length=10)
    state = models.CharField(max_length=30)
    city = models.CharField(max_length=100)
    occupation = models.CharField(max_length=20)

    def __str__(self):
        return f"{self.full_name} ({self.user_id.email})"

    def age(self):
        from datetime import date
        today = date.today()
        return today.year - self.dob.year - ((today.month, today.day) < (self.dob.month, self.dob.day))

class Transaction(BaseClass):
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    item_name = models.CharField(max_length=255)
    expected_amount = models.DecimalField(max_digits=10, decimal_places=2)
    paid_amount = models.DecimalField(max_digits=10, decimal_places=2)
    group_name = models.CharField(max_length=100, blank=True, null=True)
    note = models.TextField(blank=True, null=True)
    transaction_time = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.item_name} - ₹{self.paid_amount} ({self.user.email})"
    
class LogoutData(models.Model):
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    item_name = models.CharField(max_length=255)
    expected_amount = models.DecimalField(max_digits=10, decimal_places=2)
    paid_amount = models.DecimalField(max_digits=10, decimal_places=2)
    was_shopped = models.BooleanField(default=False)
    saved_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.item_name} - {self.user.email} - {'Shopped' if self.was_shopped else 'Unshopped'}"
