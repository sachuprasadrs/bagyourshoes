from django.db import models
from django.utils import timezone
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
import uuid


class UserDetails(models.Model):
    userid = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    address = models.TextField(blank=True, null=True, default='')
    dob = models.DateField(blank=True, null=True, default='2000-01-01')
    pincode = models.CharField(max_length=10, blank=True, null=True)
    phoneno = models.CharField(max_length=15, blank=True, null=True)

    def __str__(self):
        return f"{self.name} ({self.userid})"


class Shoes(models.Model):
    shoe_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    size = models.CharField(max_length=10)
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.ImageField(upload_to='shoes/')
    bestseller = models.BooleanField(default=False)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=20)

    def __str__(self):
        return f"{self.name} - Size {self.size}"


class Boots(models.Model):
    boot_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    size = models.CharField(max_length=10)
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.ImageField(upload_to='boots/')
    bestseller = models.BooleanField(default=False)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=20)

    def __str__(self):
        return f"{self.name} - Size {self.size}"


class ContactFormSubmission(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    message = models.TextField()
    submitted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Message from {self.name} ({self.email})"


class ContactUs(models.Model):
    shopname = models.CharField(max_length=100)
    location = models.CharField(max_length=150)
    phoneno = models.CharField(max_length=15)
    landmark = models.CharField(max_length=100)

    def __str__(self):
        return self.shopname


class Cart(models.Model):
    itemid = models.CharField(max_length=50)
    timestamp = models.DateTimeField(default=timezone.now)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    quantity = models.PositiveIntegerField()
    size = models.CharField(max_length=10)
    image = models.ImageField(upload_to='cart/')
    user_details = models.ForeignKey(UserDetails, on_delete=models.CASCADE, null=True, blank=True)
    product_type = models.CharField(max_length=10, choices=[('shoe', 'Shoe'), ('boot', 'Boot')], null=False, )

    def __str__(self):
        return f"Cart Item {self.itemid} | ₹{self.price}"


class Wishlist(models.Model):
    itemid = models.CharField(max_length=50)
    timestamp = models.DateTimeField(default=timezone.now)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.ImageField(upload_to='wishlist/')
    size = models.CharField(max_length=10)
    user_details = models.ForeignKey(UserDetails, on_delete=models.CASCADE, null=True, blank=True)
    product_type = models.CharField(max_length=10, choices=[('shoe', 'Shoe'), ('boot', 'Boot')])

    def __str__(self):
        return f"Wishlist Item {self.itemid} | Size: {self.size}"


class OrderDetails(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('processing', 'Processing'),
        ('shipped', 'Shipped'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
    ]

    orderid = models.AutoField(primary_key=True)
    productid = models.CharField(max_length=50)
    # The 'user' field is a better way to link to UserDetails.
    user = models.ForeignKey(UserDetails, on_delete=models.CASCADE, null=True, blank=True, related_name='orders', db_column='userid_id')
    username = models.CharField(max_length=100)
    useraddress = models.TextField()
    phnno = models.CharField(max_length=15)
    pincode = models.CharField(max_length=10)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    status_note = models.TextField(blank=True, null=True)
    status_updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Order #{self.orderid} by {self.username}"


class MyOrders(models.Model):
    order = models.ForeignKey(OrderDetails, on_delete=models.CASCADE, related_name='order_items')
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    product = GenericForeignKey('content_type', 'object_id')
    user_name = models.CharField(max_length=100)
    user_address = models.TextField()
    phno = models.CharField(max_length=15)
    pincode = models.CharField(max_length=10)
    quantity = models.PositiveIntegerField(default=1)
    size = models.CharField(max_length=10, default='Unknown')
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    def __str__(self):
        return f"Order #{self.order.orderid} - {self.product.name if self.product else 'Unknown'}"


class AdminLogin(models.Model):
    adminid = models.CharField(max_length=50, primary_key=True)
    password = models.CharField(max_length=128)
    phoneno = models.CharField(max_length=15)
    email = models.EmailField()

    def __str__(self):
        return f"Admin: {self.adminid}"


class PasswordResetToken(models.Model):
    user = models.ForeignKey('UserDetails', on_delete=models.CASCADE)
    token = models.CharField(max_length=100, unique=True, default=uuid.uuid4)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(hours=1)
        super().save(*args, **kwargs)

    def is_expired(self):
        return timezone.now() > self.expires_at

    class Meta:
        db_table = 'password_reset_tokens'