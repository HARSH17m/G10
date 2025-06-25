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
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=100)
    dob = models.DateField()
    gender = models.CharField(max_length=10)
    state = models.CharField(max_length=30)
    city = models.CharField(max_length=100)
    occupation = models.CharField(max_length=20)
    is_filled = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.full_name} - {self.user.email}"

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

class UserSalary(BaseClass):
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    salary = models.PositiveIntegerField(default=0)
    reset_day = models.PositiveSmallIntegerField(default=1)

    fixed_expenses = models.JSONField(default=dict)
    saving = models.PositiveIntegerField(default=0)

    emergency_percent = models.PositiveSmallIntegerField(default=10)
    personal_percent = models.PositiveSmallIntegerField(default=40)

    remaining_salary = models.PositiveIntegerField(default=0)

    def get_total_fixed_expense(self):
        return sum(self.fixed_expenses.values())

    def get_emergency_amount(self):
        return self.salary * self.emergency_percent // 100

    def get_personal_amount(self):
        return self.salary * self.personal_percent // 100

    def calculate_remaining(self):
        used = (
            self.saving +
            self.get_emergency_amount() +
            self.get_personal_amount() +
            self.get_total_fixed_expense()
        )
        return max(0, self.salary - used)

    def save(self, *args, **kwargs):
        # On creation, auto-set remaining_salary only if it's 0
        if self._state.adding and self.remaining_salary == 0:
            self.remaining_salary = self.calculate_remaining()
        # Safety check to avoid negatives
        self.remaining_salary = max(0, self.remaining_salary)
        super().save(*args, **kwargs)

    def __str__(self):
        return (
            f"{self.user.email} | ₹{self.salary} | Fixed: ₹{self.get_total_fixed_expense()} | "
            f"Saving: ₹{self.saving} | Emergency: {self.emergency_percent}% | "
            f"Personal: {self.personal_percent}% | Left: ₹{self.remaining_salary}"
        )