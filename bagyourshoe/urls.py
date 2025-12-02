"""
URL configuration for bagyourshoe project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
"""
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static

from app import views

urlpatterns = [
    # Main Admin URL (Django's built-in admin site)
    path('admin/', admin.site.urls),

    # Public Site URLs
    path('indexed/', views.indexed, name='indexed'),  # Homepage
    path('collection/', views.collection, name='collection'),
    path('contact/', views.contact, name='contact'),
    path('shoes/', views.shoes, name='shoes'),
    path('boots/', views.Boots, name='boots'),  # added from app-level urls
    path('sports/', views.sports, name='sports'),
    path('allboots/', views.all_boots, name='all_boots'),
    path('allshoes/', views.all_shoes, name='all_shoes'),
    path('cart/', views.cart, name='cart'),
    path('checkout/', views.checkout_page, name='checkout_page'),
    path('search/', views.search, name='search'),

    # Payment URLs
    path('payment/', views.payment, name='payment'),
    path('success/', views.payment_success, name='payment_success'),

    # User Authentication & Profile
    path('userreg/', views.userreg, name='userreg'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('passforgot/', views.passforgot, name='passforgot'),
    path('passreset/<str:token>/', views.passreset, name='passreset'),  # fixed to match app-level
    path('profile/', views.profile, name='profile'),
    path('myorder/', views.myorder, name='myorder'),
    path('wishlist/', views.wishlist, name='wishlist'),

    # API Endpoints (Cart & Wishlist)
    # path('add_to_cart/<str:product_type>/<int:product_id>/', views.add_to_cart, name='add_to_cart'),
    path('add-to-cart/<str:product_type>/<int:product_id>/', views.add_to_cart_v2, name='add_to_cart'),
    path('add-to-wishlist/<str:product_type>/<int:product_id>/', views.add_to_wishlist, name='add_to_wishlist'),
    path('update-cart-quantity/<int:cart_id>/', views.update_cart_quantity, name='update_cart_quantity'),
    path('remove-from-cart/<int:cart_id>/', views.remove_from_cart, name='remove_from_cart'),
    path('remove-from-wishlist/<int:wishlist_id>/', views.remove_from_wishlist, name='remove_from_wishlist'),

    # Admin Panel URLs
    path('adminhome/', views.adminhome, name='adminhome'),
    path('adminshoes/', views.adminshoes, name='adminshoes'),
    path('addshoes/', views.addshoes, name='addshoes'),
    path('editshoes/<str:category>/<int:shoe_id>/', views.editshoes, name='editshoes'),
    path('deleteshoes/<str:category>/<int:shoe_id>/', views.delete_shoes, name='delete_shoes'),
    path('userdetails/', views.userdetails, name='userdetails'),
    path('admin/orderdetails/<int:order_id>/', views.orderdetails, name='orderdetails'),

    path('ADcollection/', views.ad_collection, name='ad_collection'),
    path('ADshoes/', views.ad_shoes, name='ad_shoes'),
    path('ADsports/', views.ad_sports, name='ad_sports'),
    path('ADsearch/', views.ad_search, name='ad_search'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
