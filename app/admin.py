from django.contrib import admin
from .models import *

# Register other models

@admin.register(Shoes)
class ShoesAdmin(admin.ModelAdmin):
    list_display = ('shoe_id', 'name', 'size', 'price', 'bestseller', 'category')
    readonly_fields = ('shoe_id',)
    fieldsets = (
        (None, {
            'fields': ('shoe_id', 'name', 'size', 'quantity', 'price', 'image', 'bestseller', 'description', 'category')
        }),
    )
@admin.register(Boots)
class BootsAdmin(admin.ModelAdmin):
    list_display = ('boot_id', 'name', 'size', 'price', 'bestseller', 'category')
    readonly_fields = ('boot_id',)
    fieldsets = (
        (None, {
            'fields': ('boot_id', 'name', 'size', 'quantity', 'price', 'image', 'bestseller', 'description', 'category')
        }),
    )
admin.site.register(MyOrders)
admin.site.register(ContactUs)
admin.site.register(Cart)
admin.site.register(Wishlist)
admin.site.register(OrderDetails)
admin.site.register(AdminLogin)

# Proper registration with customization
@admin.register(UserDetails)
class UserDetailsAdmin(admin.ModelAdmin):
    list_display = ('userid', 'name', 'email')
    readonly_fields = ('userid',)
    fieldsets = (
        (None, {
            'fields': ('userid', 'name', 'email', 'password', 'address', 'dob', 'pincode', 'phoneno')
        }),
    )