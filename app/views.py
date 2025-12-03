from .models import *
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.contrib import messages
import json
import traceback
from django.core.paginator import Paginator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.conf import settings
import uuid
from datetime import datetime, timedelta
from django.utils import timezone
import razorpay
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings

# Initialize Razorpay client
razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))



def parse_wishlist_itemid(itemid):
    """
    Parse wishlist itemid (composite: 'shoe_1' or legacy: '1')
    Returns: (product_type, product_id, product_object) or (None, None, None)
    """
    parts = itemid.split('_', 1)
    if len(parts) == 2:
        item_type, item_id = parts
        try:
            if item_type == 'shoe':
                return ('shoes', item_id, Shoes.objects.get(shoe_id=item_id))
            elif item_type == 'boot':
                return ('boots', item_id, Boots.objects.get(boot_id=item_id))
        except (Shoes.DoesNotExist, Boots.DoesNotExist):
            pass
    # Legacy fallback
    try:
        return ('shoes', itemid, Shoes.objects.get(shoe_id=itemid))
    except Shoes.DoesNotExist:
        try:
            return ('boots', itemid, Boots.objects.get(boot_id=itemid))
        except Boots.DoesNotExist:
            return (None, None, None)


# Create your views here.

def passforgot(request):
    """Display forgot password form and handle password reset requests"""
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()

        if not email:
            messages.error(request, "Please enter your email address.")
            return render(request, 'passforgot.html')

        try:
            user = UserDetails.objects.get(email__iexact=email)

            # Delete any existing tokens for this user
            PasswordResetToken.objects.filter(user=user, is_used=False).delete()

            # Create new reset token
            reset_token = PasswordResetToken.objects.create(user=user)

            # Build reset URL
            current_site = get_current_site(request)
            reset_url = request.build_absolute_uri(
                reverse('passreset', kwargs={'token': reset_token.token})
            )

            # Prepare email content
            subject = 'Password Reset Request - Shoe Store'
            message = f"""
Hello {user.name},

You have requested to reset your password. Please click the link below to reset your password:

{reset_url}

This link will expire in 1 hour.

If you did not request this password reset, please ignore this email.

Best regards,
Shoe Store Team
            """

            # Send email
            try:
                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                messages.success(request,
                                 "Password reset instructions have been sent to your email address.")
                return redirect('login')

            except Exception as e:
                messages.error(request,
                               "Failed to send reset email. Please try again later.")
                print(f"Email sending error: {e}")

        except UserDetails.DoesNotExist:
            messages.success(request,
                             "If an account with this email exists, password reset instructions have been sent.")
            return redirect('login')

        except Exception as e:
            messages.error(request, "An error occurred. Please try again.")
            print(f"Forgot password error: {e}")

    return render(request, 'passforgot.html')


def passreset(request, token):
    """Handle password reset with token - UPDATED WITH PASSWORD HASHING"""
    try:
        reset_token = PasswordResetToken.objects.get(token=token, is_used=False)

        if reset_token.is_expired():
            messages.error(request, 'Password reset link has expired. Please request a new one.')
            return redirect('passforgot')

        if request.method == 'POST':
            password = request.POST.get('password', '').strip()
            confirm_password = request.POST.get('confirm_password', '').strip()

            if not password or not confirm_password:
                messages.error(request, 'Please fill in all fields.')
                return render(request, 'passreset.html', {'token': token})

            if password != confirm_password:
                messages.error(request, 'Passwords do not match.')
                return render(request, 'passreset.html', {'token': token})

            if len(password) < 6:
                messages.error(request, 'Password must be at least 6 characters long.')
                return render(request, 'passreset.html', {'token': token})

            # UPDATED: Hash the password before saving
            user = reset_token.user
            user.password = make_password(password)  # Hash the password
            user.save()

            # Mark token as used
            reset_token.is_used = True
            reset_token.save()

            messages.success(request, 'Password reset successful! Please log in with your new password.')
            return redirect('login')

        return render(request, 'passreset.html', {'token': token, 'user': reset_token.user})

    except PasswordResetToken.DoesNotExist:
        messages.error(request, 'Invalid or expired password reset link.')
        return redirect('passforgot')
    except Exception as e:
        messages.error(request, 'An error occurred. Please try again.')
        print(f'Reset password error: {e}')
        return redirect('passforgot')


def login(request):
    """User login with hashed password support"""
    if request.method == 'POST':
        u = request.POST['username'].strip()
        p = request.POST['password'].strip()

        try:
            data = UserDetails.objects.get(name__iexact=u)

            # Check if password is hashed or plain text
            if data.password.startswith('pbkdf2_'):
                # Password is hashed, use check_password
                if check_password(p, data.password):
                    request.session['username'] = data.name
                    request.session['userid'] = data.userid
                    return redirect('indexed')
                else:
                    messages.error(request, 'Wrong password')
            else:
                # Password is plain text (old users)
                if data.password == p:
                    # Migrate to hashed password on login
                    data.password = make_password(p)
                    data.save()

                    request.session['username'] = data.name
                    request.session['userid'] = data.userid
                    return redirect('indexed')
                else:
                    messages.error(request, 'Wrong password')

        except UserDetails.DoesNotExist:
            # Admin login (plain text is OK for admin)
            if u == 'admin' and p == 'admin123':
                request.session['admin'] = u
                return redirect('adminhome')
            else:
                messages.error(request, 'User not found')
        except Exception as e:
            messages.error(request, f'Unexpected error: {e}')

    return render(request, 'login.html')


def userreg(request):
    """User registration with hashed passwords"""
    if request.method == 'POST':
        name = request.POST.get('username')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        password = request.POST.get('password')

        # Validate inputs
        if not all([name, email, phone, password]):
            messages.error(request, 'Please fill in all fields.')
            return render(request, 'userreg.html')

        # Check if user already exists
        if UserDetails.objects.filter(email__iexact=email).exists():
            messages.error(request, 'Email already registered.')
            return render(request, 'userreg.html')

        # Hash the password before saving
        hashed_password = make_password(password)

        UserDetails.objects.create(
            name=name,
            email=email,
            phoneno=phone,
            password=hashed_password  # Save hashed password
        )

        messages.success(request, 'Registration successful! Please login.')
        return redirect('login')

    return render(request, 'userreg.html')


def logout(request):
    if 'username' in request.session or 'admin' in request.session:
        request.session.flush()
    return redirect('login')


def addshoes(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        size = request.POST.get('size')
        quantity = request.POST.get('quantity')
        price = request.POST.get('price')
        description = request.POST.get('description')
        category = request.POST.get('category')
        bestseller = request.POST.get('bestseller') == 'on'
        image = request.FILES.get('image')

        if category == 'casual':
            Shoes.objects.create(name=name, size=size, quantity=quantity, price=price, description=description,
                                 image=image, bestseller=bestseller, category=category)
            messages.success(request, "Shoe added to casual shoes successfully.")
        elif category == 'sports':
            Boots.objects.create(name=name, size=size, quantity=quantity, price=price, description=description,
                                 image=image, bestseller=bestseller, category=category)
            messages.success(request, "Shoe added to sports boots successfully.")
        else:
            messages.error(request, "Invalid category selected.")
        return redirect('addshoes')
    return render(request, 'admin/addshoes.html')


def editshoes(request, category, shoe_id):
    """Edit shoes/boots with proper validation"""
    if 'admin' not in request.session:
        return redirect('login')

    # Get the correct product based on category
    if category == 'casual':
        shoe = get_object_or_404(Shoes, shoe_id=shoe_id)
    elif category == 'sports':
        shoe = get_object_or_404(Boots, boot_id=shoe_id)
    else:
        messages.error(request, "Invalid category.")
        return redirect('adminshoes')

    if request.method == 'POST':
        try:
            # Get all form data with validation
            name = request.POST.get('name', '').strip()
            size = request.POST.get('size', '').strip()
            quantity = request.POST.get('quantity', '').strip()
            price = request.POST.get('price', '').strip()
            description = request.POST.get('description', '').strip()
            bestseller = request.POST.get('bestseller') == 'on'
            new_category = request.POST.get('category', category)

            # Validate required fields
            if not name:
                messages.error(request, "Product name is required.")
                return render(request, 'admin/editshoes.html', {'shoe': shoe, 'category': category})

            if not quantity:
                messages.error(request, "Quantity is required.")
                return render(request, 'admin/editshoes.html', {'shoe': shoe, 'category': category})

            if not price:
                messages.error(request, "Price is required.")
                return render(request, 'admin/editshoes.html', {'shoe': shoe, 'category': category})

            # Convert to proper types with validation
            try:
                quantity = int(quantity)
                if quantity < 0:
                    messages.error(request, "Quantity cannot be negative.")
                    return render(request, 'admin/editshoes.html', {'shoe': shoe, 'category': category})
            except ValueError:
                messages.error(request, "Invalid quantity value.")
                return render(request, 'admin/editshoes.html', {'shoe': shoe, 'category': category})

            try:
                price = float(price)
                if price < 0:
                    messages.error(request, "Price cannot be negative.")
                    return render(request, 'admin/editshoes.html', {'shoe': shoe, 'category': category})
            except ValueError:
                messages.error(request, "Invalid price value.")
                return render(request, 'admin/editshoes.html', {'shoe': shoe, 'category': category})

            # Update the product
            shoe.name = name
            shoe.size = size
            shoe.quantity = quantity
            shoe.price = price
            shoe.description = description
            shoe.bestseller = bestseller
            shoe.category = new_category

            # Handle image upload (only if new image provided)
            if request.FILES.get('image'):
                shoe.image = request.FILES.get('image')

            shoe.save()

            messages.success(request, f"{category.title()} product updated successfully.")
            return redirect('adminshoes')

        except Exception as e:
            messages.error(request, f"Error updating product: {str(e)}")
            print(f"Edit shoe error: {e}")
            import traceback
            traceback.print_exc()
            return render(request, 'admin/editshoes.html', {'shoe': shoe, 'category': category})

    # GET request - show form
    context = {
        'shoe': shoe,
        'category': category
    }
    return render(request, 'admin/editshoes.html', context)


def userdetails(request):
    users = UserDetails.objects.all()
    return render(request, 'admin/userdetails.html', {'users': users})


def adminhome(request):
    if 'admin' in request.session:
        print(request.session['admin'])
        return render(request, 'admin/adminhome.html')
    else:
        return redirect(login)


def adminshoes(request):
    """Admin shoes view with search functionality"""
    if 'admin' not in request.session:
        return redirect('login')

    # Get search query
    search_query = request.GET.get('search', '').strip()

    # Base querysets
    casualshoes = Shoes.objects.all().order_by('-shoe_id')
    sportsshoes = Boots.objects.all().order_by('-boot_id')

    # Apply search filter if query exists
    if search_query:
        from django.db.models import Q
        casualshoes = casualshoes.filter(
            Q(name__icontains=search_query) |
            Q(category__icontains=search_query) |
            Q(description__icontains=search_query)
        )
        sportsshoes = sportsshoes.filter(
            Q(name__icontains=search_query) |
            Q(category__icontains=search_query) |
            Q(description__icontains=search_query)
        )

    context = {
        'casualshoes': casualshoes,
        'sportsshoes': sportsshoes,
        'search_query': search_query,
    }
    return render(request, 'admin/adminshoes.html', context)


def orderdetails(request, order_id):
    order = get_object_or_404(OrderDetails, pk=order_id)
    customer = order.user
    items = MyOrders.objects.filter(order=order)

    # Calculate total amount and prepare items with subtotals
    total_amount = 0
    items_with_subtotal = []
    for item in items:
        subtotal = item.price * item.quantity
        total_amount += subtotal
        items_with_subtotal.append({
            'product_name': item.product.name if item.product else 'Unknown Product',
            'quantity': item.quantity,
            'price': item.price,
            'subtotal': subtotal
        })

    if request.method == 'POST':
        new_status = request.POST.get('status')
        note = request.POST.get('note', '')
        if new_status:
            order.status = new_status
            order.status_note = note
            order.status_updated_at = timezone.now()
            order.save()
            messages.success(request, f'Order status updated to {new_status.capitalize()}.')
            return redirect('admin_order_detail', order_id=order_id)

    context = {
        'order': order,
        'customer': customer,
        'items': items_with_subtotal,
        'total_amount': total_amount,
    }
    return render(request, 'admin/order_detail.html', context)


def track_order(request):
    """Track order by order ID"""
    if 'userid' not in request.session:
        messages.info(request, 'Please log in to track your orders.')
        return redirect('login')

    user = get_object_or_404(UserDetails, userid=request.session['userid'])
    order = None
    order_items = []

    if request.method == 'POST':
        order_id = request.POST.get('order_id', '').strip()

        if order_id:
            try:
                # Get order for this user only
                order = OrderDetails.objects.get(orderid=order_id, user=user)
                order_items = MyOrders.objects.filter(order=order)

                if not order_items:
                    messages.warning(request, 'No items found for this order.')
            except OrderDetails.DoesNotExist:
                messages.error(request, 'Order not found or does not belong to you.')
        else:
            messages.error(request, 'Please enter an order ID.')

    # Get all user orders for display
    user_orders = OrderDetails.objects.filter(user=user).order_by('-created_at')

    context = {
        'order': order,
        'order_items': order_items,
        'user_orders': user_orders,
        'user': user
    }

    return render(request, 'track_order.html', context)


def my_orders(request):
    """View all orders for logged-in user"""
    if 'userid' not in request.session:
        messages.info(request, 'Please log in to view your orders.')
        return redirect('login')

    user = get_object_or_404(UserDetails, userid=request.session['userid'])
    orders = OrderDetails.objects.filter(user=user).order_by('-created_at')

    # Get items for each order
    orders_with_items = []
    for order in orders:
        items = MyOrders.objects.filter(order=order)
        orders_with_items.append({
            'order': order,
            'items': items
        })

    context = {
        'orders_with_items': orders_with_items,
        'user': user
    }

    return render(request, 'my_orders.html', context)


def delete_shoes(request, category, shoe_id):
    if category == 'casual':
        shoe = get_object_or_404(Shoes, shoe_id=shoe_id)
    else:
        shoe = get_object_or_404(Boots, boot_id=shoe_id)

    if request.method == "POST" or request.method == "GET":
        shoe.delete()
        messages.success(request, f"{category.title()} Shoe deleted successfully.")
    return redirect('adminshoes')


def indexed(request):
    return render(request, 'index.html')


def collection(request):
    latest_shoes = Shoes.objects.all().order_by('-shoe_id')[:2]
    return render(request, 'collection.html', {'shoes': latest_shoes})


def search(request):
    query = request.GET.get('query', '')
    shoes_results = Shoes.objects.filter(name__icontains=query)
    boots_results = Boots.objects.filter(name__icontains=query)
    return render(request, 'search.html', {
        'query': query,
        'shoes_results': shoes_results,
        'boots_results': boots_results,
    })


def contact(request):
    store_details = ContactUs.objects.first()
    return render(request, 'contact.html', {'store': store_details})


def sports(request):
    boots = Boots.objects.all().order_by('-boot_id')[:6]
    return render(request, 'racing boots.html', {'boots': boots})


def all_boots(request):
    boots = Boots.objects.all().order_by('-boot_id')
    return render(request, 'all_boots.html', {'boots': boots})


def shoes(request):
    shoes = Shoes.objects.all().order_by('-shoe_id')[:6]
    return render(request, 'shoes.html', {
        'shoes': shoes,
        'product_type': 'shoes'
    })


def all_shoes(request):
    shoes = Shoes.objects.all().order_by('-shoe_id')
    return render(request, 'all_shoes.html', {'shoes': shoes})


def profile(request):
    return render(request, 'profile.html')


from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
import logging

# Add logging to help debug
logger = logging.getLogger(__name__)


@csrf_exempt  # Add this decorator
@require_POST  # Ensure only POST requests
def add_to_cart(request, product_type, product_id):
    try:
        # Log the request for debugging
        logger.info(f"Add to cart request: product_type={product_type}, product_id={product_id}")
        logger.info(f"POST data: {request.POST}")
        logger.info(f"User session: {request.session.get('userid', 'No user')}")

        # Get and validate inputs
        try:
            quantity = int(request.POST.get('quantity', 1))
            if quantity <= 0:
                return JsonResponse({'error': 'Quantity must be greater than 0'}, status=400)
        except (ValueError, TypeError):
            return JsonResponse({'error': 'Invalid quantity value'}, status=400)

        size = request.POST.get('size', '').strip()
        if not size:
            return JsonResponse({'error': 'Please select a size'}, status=400)

        # Determine product model and get product
        product = None
        model_class = None

        if product_type == 'shoes':
            try:
                product = Shoes.objects.get(shoe_id=product_id)
                model_class = 'shoe'  # This must match your Cart model choices
            except Shoes.DoesNotExist:
                return JsonResponse({'error': 'Product not found'}, status=404)

        elif product_type == 'boots':
            try:
                product = Boots.objects.get(boot_id=product_id)
                model_class = 'boot'  # This must match your Cart model choices
            except Boots.DoesNotExist:
                return JsonResponse({'error': 'Product not found'}, status=404)
        else:
            return JsonResponse({'error': 'Invalid product type'}, status=400)

        # Check stock availability
        if product.quantity < quantity:
            return JsonResponse({
                'error': f'Insufficient stock. Only {product.quantity} items available'
            }, status=400)

        # Handle logged-in users
        if 'userid' in request.session:
            try:
                user = UserDetails.objects.get(userid=request.session['userid'])
                logger.info(f"Found user: {user.name}")

                # Check for existing cart item
                existing_cart_item = Cart.objects.filter(
                    user_details=user,
                    itemid=str(product_id),
                    size=size,
                    product_type=model_class
                ).first()

                if existing_cart_item:
                    # Update existing item
                    new_total_quantity = existing_cart_item.quantity + quantity
                    if new_total_quantity > product.quantity:
                        return JsonResponse({
                            'error': f'Total quantity would exceed available stock ({product.quantity})'
                        }, status=400)

                    existing_cart_item.quantity = new_total_quantity
                    existing_cart_item.save()
                    logger.info(f"Updated existing cart item: {existing_cart_item.id}")
                else:
                    # Create new cart item
                    cart_item = Cart.objects.create(
                        user_details=user,
                        itemid=str(product_id),
                        price=product.price,
                        quantity=quantity,
                        size=size,
                        image=product.image,
                        product_type=model_class
                    )
                    logger.info(f"Created new cart item: {cart_item.id}")

            except UserDetails.DoesNotExist:
                logger.error(f"User not found with userid: {request.session['userid']}")
                return JsonResponse({'error': 'User session expired'}, status=401)

        # Handle guest users
        else:
            logger.info("Processing guest user cart")
            guest_cart = request.session.get('guest_cart', [])

            # Find existing item
            item_found = False
            for item in guest_cart:
                if (str(item.get('itemid')) == str(product_id) and
                        item.get('product_type') == model_class and
                        item.get('size') == size):

                    new_total_quantity = item['quantity'] + quantity
                    if new_total_quantity > product.quantity:
                        return JsonResponse({
                            'error': f'Total quantity would exceed available stock ({product.quantity})'
                        }, status=400)

                    item['quantity'] = new_total_quantity
                    item_found = True
                    logger.info(f"Updated guest cart item: {product_id}")
                    break

            if not item_found:
                # Add new item to guest cart
                new_item = {
                    'itemid': str(product_id),
                    'price': float(product.price),
                    'quantity': quantity,
                    'size': size,
                    'image_url': product.image.url if product.image else '',
                    'product_type': model_class,
                    'name': product.name
                }
                guest_cart.append(new_item)
                logger.info(f"Added new guest cart item: {product_id}")

            # Save updated cart to session
            request.session['guest_cart'] = guest_cart
            request.session.modified = True

        return JsonResponse({
            'success': True,
            'message': 'Item added to cart successfully',
            'product_name': product.name,
            'quantity_added': quantity
        })

    except Exception as e:
        logger.error(f"Unexpected error in add_to_cart: {str(e)}", exc_info=True)
        return JsonResponse({
            'error': f'An unexpected error occurred: {str(e)}'
        }, status=500)


def get_cart_count(request):
    count = 0
    if 'userid' in request.session:
        user = UserDetails.objects.get(userid=request.session['userid'])
        count = Cart.objects.filter(user_details=user).count()
    else:
        guest_cart = request.session.get('guest_cart', [])
        count = len(guest_cart)

    return JsonResponse({'count': count})


# Alternative version with better error handling
def add_to_cart_v2(request, product_type, product_id):
    """Improved version with detailed error logging"""

    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    # Validate inputs step by step
    errors = []

    # Validate quantity
    quantity_str = request.POST.get('quantity', '1')
    try:
        quantity = int(quantity_str)
        if quantity <= 0:
            errors.append('Quantity must be greater than 0')
    except (ValueError, TypeError):
        errors.append(f'Invalid quantity: {quantity_str}')
        quantity = 1  # fallback

    # Validate size
    size = request.POST.get('size', '').strip()
    if not size:
        errors.append('Size is required')

    # Validate product type and get product
    product = None
    model_class = None

    if product_type not in ['shoes', 'boots']:
        errors.append(f'Invalid product type: {product_type}')
    else:
        try:
            if product_type == 'shoes':
                product = Shoes.objects.get(shoe_id=product_id)
                model_class = 'shoe'
            else:  # boots
                product = Boots.objects.get(boot_id=product_id)
                model_class = 'boot'
        except (Shoes.DoesNotExist, Boots.DoesNotExist):
            errors.append(f'Product not found: {product_type} with ID {product_id}')

    # Return validation errors if any
    if errors:
        return JsonResponse({
            'error': 'Validation failed',
            'details': errors
        }, status=400)

    # Check stock
    if product.quantity < quantity:
        return JsonResponse({
            'error': f'Insufficient stock. Available: {product.quantity}, Requested: {quantity}'
        }, status=400)

    try:
        # Process cart addition
        if 'userid' in request.session:
            user = UserDetails.objects.get(userid=request.session['userid'])

            existing_item = Cart.objects.filter(
                user_details=user,
                itemid=str(product_id),
                size=size,
                product_type=model_class
            ).first()

            if existing_item:
                if existing_item.quantity + quantity > product.quantity:
                    return JsonResponse({
                        'error': f'Would exceed stock limit. Current in cart: {existing_item.quantity}, Stock: {product.quantity}'
                    }, status=400)
                existing_item.quantity += quantity
                existing_item.save()
                action = 'updated'
            else:
                Cart.objects.create(
                    user_details=user,
                    itemid=str(product_id),
                    price=product.price,
                    quantity=quantity,
                    size=size,
                    image=product.image,
                    product_type=model_class
                )
                action = 'added'

        else:  # Guest user
            guest_cart = request.session.get('guest_cart', [])

            existing_item = None
            for item in guest_cart:
                if (str(item.get('itemid')) == str(product_id) and
                        item.get('product_type') == model_class and
                        item.get('size') == size):
                    existing_item = item
                    break

            if existing_item:
                if existing_item['quantity'] + quantity > product.quantity:
                    return JsonResponse({
                        'error': f'Would exceed stock limit. Current in cart: {existing_item["quantity"]}, Stock: {product.quantity}'
                    }, status=400)
                existing_item['quantity'] += quantity
                action = 'updated'
            else:
                guest_cart.append({
                    'itemid': str(product_id),
                    'price': float(product.price),
                    'quantity': quantity,
                    'size': size,
                    'image_url': product.image.url if product.image else '',
                    'product_type': model_class,
                    'name': product.name
                })
                action = 'added'

            request.session['guest_cart'] = guest_cart
            request.session.modified = True

        return JsonResponse({
            'success': True,
            'message': f'Item {action} successfully',
            'product_name': product.name,
            'action': action,
            'quantity': quantity
        })

    except Exception as e:
        return JsonResponse({
            'error': f'Database error: {str(e)}'
        }, status=500)


def add_to_wishlist(request, product_type, product_id):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=400)

    try:
        # Normalize product_type
        if product_type in ['shoe', 'shoes']:
            product = get_object_or_404(Shoes, shoe_id=product_id)
            normalized_type = 'shoe'
        elif product_type in ['boot', 'boots']:
            product = get_object_or_404(Boots, boot_id=product_id)
            normalized_type = 'boot'
        else:
            return JsonResponse({'error': 'Invalid product type'}, status=400)

        # Composite key
        composite_itemid = f"{normalized_type}_{product_id}"

        if 'userid' in request.session:
            user = get_object_or_404(UserDetails, userid=request.session['userid'])
            existing = Wishlist.objects.filter(itemid=composite_itemid, user_details=user).first()

            if existing:
                return JsonResponse({'success': True, 'message': 'Item already in wishlist', 'action': 'exists'})
            else:
                Wishlist.objects.create(
                    user_details=user, itemid=composite_itemid,
                    price=product.price, size=product.size, image=product.image
                )
                return JsonResponse({'success': True, 'message': 'Item added to wishlist', 'action': 'added'})
        else:
            guest_wishlist = request.session.get('guest_wishlist', [])
            if any(item['itemid'] == composite_itemid for item in guest_wishlist):
                return JsonResponse({'success': True, 'message': 'Item already in wishlist', 'action': 'exists'})

            guest_wishlist.append({
                'itemid': composite_itemid, 'price': float(product.price),
                'size': product.size, 'image_url': product.image.url,
                'product_type': normalized_type, 'name': product.name
            })
            request.session['guest_wishlist'] = guest_wishlist
            request.session.modified = True
            return JsonResponse({'success': True, 'message': 'Item added to wishlist', 'action': 'added'})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def cart(request):
    """
    Cart view with integrated wishlist tab support
    Displays both cart items and wishlist items for tabbed interface
    """
    cart_items_display = []
    wishlist_items_display = []
    total_price = 0

    # ==================== CART ITEMS ====================
    # Logged-in user cart
    if 'userid' in request.session:
        try:
            user = UserDetails.objects.get(userid=request.session['userid'])
            cart_data_queryset = Cart.objects.filter(user_details=user).select_related('user_details')

            if not cart_data_queryset.exists():
                print("No cart items found for user")

            cart_items_list = list(cart_data_queryset)

            for cart_item in cart_items_list:
                product = None
                try:
                    product_type = getattr(cart_item, 'product_type', None)

                    if not product_type:
                        print(f"Warning: Cart item {cart_item.id} has no product_type")
                        continue

                    if product_type == 'shoe':
                        try:
                            product = Shoes.objects.get(shoe_id=cart_item.itemid)
                        except Shoes.DoesNotExist:
                            print(f"Shoe with ID {cart_item.itemid} not found")
                            continue
                    elif product_type == 'boot':
                        try:
                            product = Boots.objects.get(boot_id=cart_item.itemid)
                        except Boots.DoesNotExist:
                            print(f"Boot with ID {cart_item.itemid} not found")
                            continue
                    else:
                        print(f"Unknown product_type: {product_type}")
                        continue

                except Exception as e:
                    print(f"Error processing cart item {cart_item.id}: {e}")
                    continue

                if product:
                    try:
                        subtotal = cart_item.price * cart_item.quantity
                        total_price += subtotal
                        cart_items_display.append({
                            'id': cart_item.pk,
                            'product_obj': product,
                            'name': product.name,
                            'image_url': product.image.url if product.image else '',
                            'price': product.price,
                            'quantity': cart_item.quantity,
                            'size': cart_item.size,
                            'subtotal': subtotal,
                            'product_type': product_type,
                            'product_id': cart_item.itemid
                        })
                    except Exception as e:
                        print(f"Error calculating subtotal for item {cart_item.id}: {e}")
                        continue

            # ==================== WISHLIST ITEMS (for logged-in user) ====================
            try:
                wishlist_data_queryset = Wishlist.objects.filter(user_details=user)

                for wishlist_item in wishlist_data_queryset:
                    product = None
                    product_type = None
                    product_id = None

                    # Parse composite itemid using helper function
                    product_type, product_id, product = parse_wishlist_itemid(wishlist_item.itemid)

                    if not product:
                        continue

                    if product:
                        wishlist_items_display.append({
                            'id': wishlist_item.pk,
                            'product_obj': product,
                            'name': product.name,
                            'image_url': product.image.url if product.image else '',
                            'price': product.price,
                            'category': product.category,
                            'product_type': product_type,
                            'product_id': product_id
                        })

            except Exception as e:
                print(f"Error loading wishlist in cart view: {e}")

        except UserDetails.DoesNotExist:
            messages.error(request, "Session expired. Please log in again.")
            request.session.flush()
            return redirect('login')
        except Exception as e:
            print(f"Unexpected error in cart view: {e}")
            import traceback
            traceback.print_exc()
            messages.error(request, "An error occurred while loading your cart.")
            return redirect('indexed')

    # ==================== GUEST USER CART ====================
    else:
        session_cart = request.session.get('guest_cart', [])
        for item_dict in session_cart:
            item_id = item_dict.get('itemid')
            product = None
            product_type = item_dict.get('product_type')

            try:
                if product_type == 'shoe':
                    product = Shoes.objects.get(shoe_id=item_id)
                elif product_type == 'boot':
                    product = Boots.objects.get(boot_id=item_id)
            except (Shoes.DoesNotExist, Boots.DoesNotExist):
                continue

            if product:
                item_price = item_dict.get('price', 0)
                item_quantity = item_dict.get('quantity', 0)
                subtotal = item_price * item_quantity
                total_price += subtotal
                cart_items_display.append({
                    'id': item_id,
                    'product_obj': product,
                    'name': item_dict.get('name'),
                    'image_url': item_dict.get('image_url'),
                    'price': item_price,
                    'quantity': item_quantity,
                    'size': item_dict.get('size', 'N/A'),
                    'subtotal': subtotal,
                    'product_type': product_type,
                    'product_id': item_id
                })

        if not cart_items_display and 'guest_cart' in request.session:
            del request.session['guest_cart']
            request.session.modified = True

        # ==================== GUEST USER WISHLIST ====================
        session_wishlist = request.session.get('guest_wishlist', [])
        for item_dict in session_wishlist:
            item_id = item_dict.get('itemid')
            product = None
            product_type = item_dict.get('product_type')

            try:
                if product_type == 'shoes':
                    product = Shoes.objects.get(shoe_id=item_id)
                elif product_type == 'boots':
                    product = Boots.objects.get(boot_id=item_id)
            except (Shoes.DoesNotExist, Boots.DoesNotExist):
                continue

            if product:
                wishlist_items_display.append({
                    'id': item_id,
                    'product_obj': product,
                    'name': item_dict.get('name'),
                    'image_url': item_dict.get('image_url'),
                    'price': item_dict.get('price', 0),
                    'category': getattr(product, 'category', 'N/A'),
                    'product_type': product_type,
                    'product_id': item_id
                })

    context = {
        'cart_items': cart_items_display,
        'total_amount': total_price,  # Changed from total_price to match template
        'wishlist_items': wishlist_items_display,  # Added for tabbed interface
    }
    return render(request, 'cart.html', context)


def wishlist(request):
    """
    Standalone wishlist page view
    Provides dedicated wishlist access at /wishlist/ URL
    """
    wishlist_items_display = []

    # Logged-in user wishlist
    if 'userid' in request.session:
        try:
            user = get_object_or_404(UserDetails, userid=request.session['userid'])
            wishlist_data_queryset = Wishlist.objects.filter(user_details=user)

            for wishlist_item in wishlist_data_queryset:
                product = None
                product_type = None
                product_id = None

                # Parse composite itemid using helper function
                product_type, product_id, product = parse_wishlist_itemid(wishlist_item.itemid)

                if not product:
                    continue

                if product:
                    wishlist_items_display.append({
                        'id': wishlist_item.pk,
                        'product_obj': product,
                        'name': product.name,
                        'image_url': product.image.url if product.image else '',
                        'price': product.price,
                        'category': getattr(product, 'category', 'N/A'),
                        'product_type': product_type,
                        'product_id': product_id
                    })

        except Exception as e:
            messages.error(request, f"Error loading wishlist: {e}")
            import traceback
            traceback.print_exc()

    # Guest user wishlist
    else:
        session_wishlist = request.session.get('guest_wishlist', [])

        for item_dict in session_wishlist:
            item_id = item_dict.get('itemid')
            product = None
            product_type = item_dict.get('product_type')

            try:
                if product_type == 'shoes':
                    product = Shoes.objects.get(shoe_id=item_id)
                elif product_type == 'boots':
                    product = Boots.objects.get(boot_id=item_id)
            except (Shoes.DoesNotExist, Boots.DoesNotExist):
                continue

            if product:
                wishlist_items_display.append({
                    'id': item_id,
                    'product_obj': product,
                    'name': item_dict.get('name'),
                    'image_url': item_dict.get('image_url'),
                    'price': item_dict.get('price', 0),
                    'category': getattr(product, 'category', 'N/A'),
                    'product_type': product_type,
                    'product_id': item_id
                })

    context = {
        'wishlist_items': wishlist_items_display,
    }
    return render(request, 'wishlist.html', context)


def update_cart_quantity(request, cart_id):
    if request.method == 'POST':
        try:
            new_quantity = int(request.POST.get('quantity', 1))

            # For logged-in users
            if 'userid' in request.session:
                user = get_object_or_404(UserDetails, userid=request.session['userid'])
                cart_item = get_object_or_404(Cart, pk=cart_id, user_details=user)

                if new_quantity > 0:
                    cart_item.quantity = new_quantity
                    cart_item.save()
                    return JsonResponse({'success': True, 'message': 'Cart updated successfully'})
                else:
                    cart_item.delete()
                    return JsonResponse({'success': True, 'message': 'Item removed from cart'})

            # For guest users
            else:
                guest_cart = request.session.get('guest_cart', [])
                for i, item in enumerate(guest_cart):
                    # For guest users, `cart_id` is the `itemid`
                    if item.get('itemid') == str(cart_id):
                        if new_quantity > 0:
                            guest_cart[i]['quantity'] = new_quantity
                        else:
                            del guest_cart[i]
                        break

                request.session['guest_cart'] = guest_cart
                request.session.modified = True
                return JsonResponse({'success': True, 'message': 'Cart updated successfully'})

        except ValueError:
            return JsonResponse({'error': 'Invalid quantity'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


def remove_from_cart(request, cart_id):
    if request.method == 'POST':
        try:
            # For logged-in users
            if 'userid' in request.session:
                user = get_object_or_404(UserDetails, userid=request.session['userid'])
                cart_item = get_object_or_404(Cart, pk=cart_id, user_details=user)
                cart_item.delete()
                return JsonResponse({'success': True, 'message': 'Item removed from cart'})

            # For guest users
            else:
                guest_cart = request.session.get('guest_cart', [])
                for i, item in enumerate(guest_cart):
                    # For guest user, the 'cart_id' is the 'itemid'
                    if item['itemid'] == str(cart_id):
                        del guest_cart[i]
                        break

                request.session['guest_cart'] = guest_cart
                request.session.modified = True
                return JsonResponse({'success': True, 'message': 'Item removed from cart'})

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


def checkout_page(request):
    # Check if user is authenticated - redirect to login if not
    if 'userid' not in request.session:
        messages.info(request, "Please log in to checkout.")
        return redirect('login')

    cart_items_display = []
    total_price = 0

    try:
        user = UserDetails.objects.get(userid=request.session['userid'])
        cart_data_queryset = Cart.objects.filter(user_details=user)

        # If cart is empty, redirect to cart page
        if not cart_data_queryset.exists():
            messages.info(request, "Your cart is empty. Please add items before checkout.")
            return redirect('cart')

        for cart_item in cart_data_queryset:
            product = None
            try:
                # Use product_type to determine the model
                if cart_item.product_type == 'shoe':
                    product = Shoes.objects.get(shoe_id=cart_item.itemid)
                elif cart_item.product_type == 'boot':
                    product = Boots.objects.get(boot_id=cart_item.itemid)
            except (Shoes.DoesNotExist, Boots.DoesNotExist):
                continue

            if product:
                subtotal = cart_item.price * cart_item.quantity
                total_price += subtotal
                cart_items_display.append({
                    'id': cart_item.pk,
                    'product_obj': product,
                    'name': product.name,
                    'image_url': product.image.url if product.image else '',
                    'price': product.price,
                    'quantity': cart_item.quantity,
                    'size': cart_item.size,
                    'subtotal': subtotal,
                    'product_type': 'shoes' if cart_item.product_type == 'shoe' else 'boots',
                    'product_id': cart_item.itemid
                })


    except UserDetails.DoesNotExist:
        messages.error(request, "Session expired. Please log in again.")
        request.session.flush()
        return redirect('login')
    except Exception as e:
        messages.error(request, f"An error occurred: {str(e)}")
        return redirect('cart')

    context = {
        'cart_items': cart_items_display,
        'total_price': total_price,
        'user': user
    }
    return render(request, 'checkout.html', context)


def payment(request):
    """Handle payment and send order confirmation email"""
    if 'userid' not in request.session:
        messages.info(request, 'Please log in to complete your purchase.')
        return redirect('login')

    if request.method == 'POST':
        try:
            total_amount = float(request.POST.get('total_amount', 0))
            payment_method = request.POST.get('payment_method', 'cod')
            address = request.POST.get('address', '')

            if total_amount <= 0:
                messages.error(request, 'Invalid cart amount.')
                return redirect('cart')

            if not address.strip():
                messages.error(request, 'Shipping address is required.')
                return redirect('checkout_page')

            # Get user
            user = get_object_or_404(UserDetails, userid=request.session['userid'])

            # Get cart items
            cart_data_queryset = Cart.objects.filter(user_details=user)

            if not cart_data_queryset.exists():
                messages.error(request, 'Your cart is empty.')
                return redirect('cart')

            # ✅ Create order - OrderDetails uses username, useraddress (NO underscores)
            order = OrderDetails.objects.create(
                user=user,
                username=user.name,           # ✅ NO underscore
                useraddress=address,          # ✅ NO underscore
                phnno=request.POST.get('phone', user.phoneno if user.phoneno else 'N/A'),
                pincode=request.POST.get('pincode', user.pincode if user.pincode else 'N/A'),
                status='pending'
            )

            # Create order items
            order_items = []
            for cart_item in cart_data_queryset:
                product = None
                if cart_item.product_type == 'shoe':
                    product = Shoes.objects.get(shoe_id=cart_item.itemid)
                    content_type = ContentType.objects.get_for_model(Shoes)
                    object_id = cart_item.itemid
                elif cart_item.product_type == 'boot':
                    product = Boots.objects.get(boot_id=cart_item.itemid)
                    content_type = ContentType.objects.get_for_model(Boots)
                    object_id = cart_item.itemid

                if product:
                    # ✅ Create MyOrders entry - MyOrders uses user_name, user_address (WITH underscores)
                    order_item = MyOrders.objects.create(
                        order=order,
                        content_type=content_type,
                        object_id=object_id,
                        user_name=user.name,          # ✅ WITH underscore
                        user_address=address,         # ✅ WITH underscore
                        phno=request.POST.get('phone', user.phoneno if user.phoneno else 'N/A'),
                        pincode=request.POST.get('pincode', user.pincode if user.pincode else 'N/A'),
                        quantity=cart_item.quantity,
                        size=cart_item.size,
                        price=cart_item.price
                    )
                    order_items.append(order_item)

                    # Reduce product quantity
                    if product.quantity >= cart_item.quantity:
                        product.quantity -= cart_item.quantity
                        product.save()

            # Handle COD payment
            if payment_method == 'cod':
                # Update order status
                order.status = 'confirmed'
                order.save()

                # Clear cart
                cart_data_queryset.delete()

                # Send order confirmation email
                try:
                    subject = f"Order Confirmation - Order #{order.orderid}"
                    html_message = render_to_string('order_confirmation_email.html', {
                        'user': user,
                        'order': order,
                        'items': order_items,
                    })
                    send_mail(
                        subject=subject,
                        message='',
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[user.email],
                        html_message=html_message,
                        fail_silently=True,
                    )
                    print(f"✅ Order confirmation email sent to {user.email}")
                    messages.info(request, f'Order confirmation sent to {user.email}')
                except Exception as e:
                    print(f"❌ Failed to send order confirmation email: {e}")

                # Clear pending order from session
                if 'pending_order_id' in request.session:
                    del request.session['pending_order_id']

                context = {
                    'total_amount': total_amount,
                    'payment_method': payment_method,
                    'address': address,
                    'order_id': order.orderid
                }

                messages.success(request, 'Order placed successfully! You will pay cash on delivery.')
                return render(request, 'payment.html', context)

            # Handle Razorpay payment
            elif payment_method == 'razorpay':
                try:
                    razorpay_order = razorpay_client.order.create({
                        'amount': int(total_amount * 100),
                        'currency': 'INR',
                        'payment_capture': 1
                    })

                    # Store order_id in session for Razorpay callback
                    request.session['pending_order_id'] = order.orderid

                    context = {
                        'razorpay_key': settings.RAZORPAY_KEY_ID,
                        'razorpay_amount': int(total_amount * 100),
                        'payment': razorpay_order,
                        'total_amount': total_amount,
                        'payment_method': payment_method,
                        'address': address,
                        'user': user,
                        'order_id': order.orderid
                    }

                    return render(request, 'payment.html', context)

                except Exception as e:
                    messages.error(request, 'Failed to initialize payment gateway. Please try again.')
                    print(f'Razorpay error: {e}')
                    order.delete()
                    return redirect('checkout_page')

        except UserDetails.DoesNotExist:
            messages.error(request, 'User session expired. Please log in again.')
            request.session.flush()
            return redirect('login')
        except ValueError as e:
            messages.error(request, 'Invalid amount provided.')
            return redirect('checkout_page')
        except Exception as e:
            messages.error(request, f'An error occurred during payment: {str(e)}')
            print(f'Payment error: {e}')
            traceback.print_exc()
            return redirect('checkout_page')

    return redirect('checkout_page')


def payment_success(request):
    """Handle successful payment callback - Clear cart here for Razorpay"""
    if request.method == 'POST':
        order_id = request.POST.get('order_id')

        try:
            order = get_object_or_404(OrderDetails, orderid=order_id)

            # Update order status to confirmed
            order.status = 'confirmed'
            order.save()

            # NOW clear the cart after successful payment
            if 'userid' in request.session:
                user = get_object_or_404(UserDetails, userid=request.session['userid'])
                Cart.objects.filter(user_details=user).delete()

            # Clear pending order from session
            if 'pending_order_id' in request.session:
                del request.session['pending_order_id']

            # Send confirmation email
            try:
                subject = 'Order Confirmation - Shoe Store'
                message = render_to_string('order_confirmation_email.html', {
                    'user': order.user,
                    'order': order,
                    'items': MyOrders.objects.filter(order=order)
                })
                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    [order.user.email] if order.user else [settings.DEFAULT_FROM_EMAIL],
                    fail_silently=True
                )
            except Exception as e:
                print(f"Email sending error: {e}")

            messages.success(request, "Payment successful! Order confirmation has been sent to your email.")
            return redirect('myorder')

        except OrderDetails.DoesNotExist:
            messages.error(request, "Invalid order.")
            return redirect('cart')

    return redirect('myorder')


def remove_from_wishlist(request, wishlist_id):
    if request.method == 'POST':
        try:
            # For logged-in users
            if 'userid' in request.session:
                user = get_object_or_404(UserDetails, userid=request.session['userid'])
                wishlist_item = get_object_or_404(Wishlist, pk=wishlist_id, user_details=user)
                wishlist_item.delete()
                return JsonResponse({'success': True, 'message': 'Item removed from wishlist'})

            # For guest users
            else:
                guest_wishlist = request.session.get('guest_wishlist', [])
                for i, item in enumerate(guest_wishlist):
                    # For guest user, the 'wishlist_id' is the 'itemid'
                    if item['itemid'] == str(wishlist_id):
                        del guest_wishlist[i]
                        break

                request.session['guest_wishlist'] = guest_wishlist
                request.session.modified = True
                return JsonResponse({'success': True, 'message': 'Item removed from wishlist'})

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


def admin_manage_orders(request):
    """Admin view to manage all orders with filters and search"""
    if 'admin' not in request.session:
        return redirect('login')

    # Get filter parameters
    status_filter = request.GET.get('status', '')
    search_query = request.GET.get('search', '')

    orders = OrderDetails.objects.all().order_by('-created_at')

    # Apply filters
    if status_filter:
        orders = orders.filter(status=status_filter)

    if search_query:
        from django.db.models import Q
        orders = orders.filter(
            Q(orderid__icontains=search_query) |
            Q(username__icontains=search_query) |
            Q(phnno__icontains=search_query)
        )

    # Calculate total for each order
    orders_with_totals = []
    for order in orders:
        items = MyOrders.objects.filter(order=order)
        total = sum(item.price * item.quantity for item in items)
        order.calculated_total = total  # Add calculated total to order object
        orders_with_totals.append(order)

    # Pagination
    paginator = Paginator(orders_with_totals, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Get status counts
    status_counts = {
        'all': OrderDetails.objects.count(),
        'pending': OrderDetails.objects.filter(status='pending').count(),
        'confirmed': OrderDetails.objects.filter(status='confirmed').count(),
        'processing': OrderDetails.objects.filter(status='processing').count(),
        'shipped': OrderDetails.objects.filter(status='shipped').count(),
        'delivered': OrderDetails.objects.filter(status='delivered').count(),
        'cancelled': OrderDetails.objects.filter(status='cancelled').count(),
    }

    context = {
        'page_obj': page_obj,
        'status_counts': status_counts,
        'current_status': status_filter,
        'search_query': search_query,
    }

    return render(request, 'admin/manage_orders.html', context)


def myorder(request):
    return render(request, 'myorder.html')


def ad_collection(request):
    if 'admin' not in request.session:
        return redirect('login')
    latest_shoes = Shoes.objects.all().order_by('-shoe_id')[:2]
    return render(request, 'admin/ADcollection.html', {'shoes': latest_shoes})


def ad_shoes(request):
    if 'admin' not in request.session:
        return redirect('login')
    shoes = Shoes.objects.all().order_by('-shoe_id')
    return render(request, 'admin/ADshoes.html', {'shoes': shoes})


def ad_sports(request):
    if 'admin' not in request.session:
        return redirect('login')
    boots = Boots.objects.all().order_by('-boot_id')
    return render(request, 'admin/ADracing boots.html', {'boots': boots})


def ad_search(request):
    """Admin search view with empty query handling"""
    if 'admin' not in request.session:
        return redirect('login')

    query = request.GET.get('query', '').strip()

    # Initialize empty results
    shoes_results = []
    boots_results = []

    # Only search if query is not empty
    if query:
        from django.db.models import Q
        shoes_results = Shoes.objects.filter(
            Q(name__icontains=query) |
            Q(category__icontains=query)
        )
        boots_results = Boots.objects.filter(
            Q(name__icontains=query) |
            Q(category__icontains=query)
        )

    return render(request, 'admin/ADsearch.html', {
        'query': query,
        'shoes_results': shoes_results,
        'boots_results': boots_results
    })
