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
from django.db.models import Q
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
import logging

# Initialize Razorpay client
razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
logger = logging.getLogger(__name__)


# --- Helper Functions ---

def parse_wishlist_itemid(itemid):
    """Parse wishlist itemid and return product type, id, and object."""
    try:
        if itemid.startswith('shoe_'):
            numeric_id = int(itemid.split('_')[1])
            return ('shoes', itemid, Shoes.objects.get(shoe_id=numeric_id))
        elif itemid.startswith('boot_'):
            numeric_id = int(itemid.split('_')[1])
            return ('boots', itemid, Boots.objects.get(boot_id=numeric_id))
        else:
            # Fallback for old/simple numeric IDs if any
            return (None, itemid, None)
    except (IndexError, ValueError, Shoes.DoesNotExist, Boots.DoesNotExist) as e:
        print(f"Error parsing itemid '{itemid}': {e}")
        return (None, itemid, None)


# --- Auth Views ---

def passforgot(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        if not email:
            messages.error(request, "Please enter your email address.")
            return render(request, 'passforgot.html')
        try:
            user = UserDetails.objects.get(email__iexact=email)
            PasswordResetToken.objects.filter(user=user, is_used=False).delete()
            reset_token = PasswordResetToken.objects.create(user=user)
            reset_url = request.build_absolute_uri(reverse('passreset', kwargs={'token': reset_token.token}))
            subject = 'Password Reset Request - Shoe Store'
            message = f"Click to reset: {reset_url}"
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)
            messages.success(request, "Password reset instructions sent.")
            return redirect('login')
        except UserDetails.DoesNotExist:
            messages.success(request, "If an account exists, instructions have been sent.")
            return redirect('login')
        except Exception as e:
            messages.error(request, "An error occurred.")
            print(f"Forgot password error: {e}")
    return render(request, 'passforgot.html')


def passreset(request, token):
    try:
        reset_token = PasswordResetToken.objects.get(token=token, is_used=False)
        if reset_token.is_expired():
            messages.error(request, 'Link expired.')
            return redirect('passforgot')
        if request.method == 'POST':
            password = request.POST.get('password', '').strip()
            confirm = request.POST.get('confirm_password', '').strip()
            if password != confirm:
                messages.error(request, 'Passwords do not match.')
                return render(request, 'passreset.html', {'token': token})
            if len(password) < 6:
                messages.error(request, 'Password too short.')
                return render(request, 'passreset.html', {'token': token})
            user = reset_token.user
            user.password = make_password(password)
            user.save()
            reset_token.is_used = True
            reset_token.save()
            messages.success(request, 'Password reset successful.')
            return redirect('login')
        return render(request, 'passreset.html', {'token': token})
    except PasswordResetToken.DoesNotExist:
        messages.error(request, 'Invalid link.')
        return redirect('passforgot')


def login(request):
    if request.method == 'POST':
        u = request.POST['username'].strip()
        p = request.POST['password'].strip()
        try:
            data = UserDetails.objects.get(name__iexact=u)
            if data.password.startswith('pbkdf2_'):
                if check_password(p, data.password):
                    request.session['username'] = data.name
                    request.session['userid'] = data.userid
                    return redirect('indexed')
                else:
                    messages.error(request, 'Wrong password')
            else:
                if data.password == p:
                    data.password = make_password(p)
                    data.save()
                    request.session['username'] = data.name
                    request.session['userid'] = data.userid
                    return redirect('indexed')
                else:
                    messages.error(request, 'Wrong password')
        except UserDetails.DoesNotExist:
            if u == 'admin' and p == 'admin123':
                request.session['admin'] = u
                return redirect('adminhome')
            else:
                messages.error(request, 'User not found')
    return render(request, 'login.html')


def userreg(request):
    if request.method == 'POST':
        name = request.POST.get('username')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        password = request.POST.get('password')
        if UserDetails.objects.filter(email__iexact=email).exists():
            messages.error(request, 'Email already registered.')
            return render(request, 'userreg.html')
        UserDetails.objects.create(name=name, email=email, phoneno=phone, password=make_password(password))
        messages.success(request, 'Registration successful! Please login.')
        return redirect('login')
    return render(request, 'userreg.html')


def logout(request):
    request.session.flush()
    return redirect('login')


# --- Product & Admin Views ---

def addshoes(request):
    if request.method == 'POST':
        category = request.POST.get('category')
        data = {
            'name': request.POST.get('name'),
            'size': request.POST.get('size'),
            'quantity': request.POST.get('quantity'),
            'price': request.POST.get('price'),
            'description': request.POST.get('description'),
            'bestseller': request.POST.get('bestseller') == 'on',
            'image': request.FILES.get('image'),
            'category': category
        }
        if category == 'casual':
            Shoes.objects.create(**data)
        elif category == 'sports':
            Boots.objects.create(**data)
        messages.success(request, "Shoe added successfully.")
        return redirect('addshoes')
    return render(request, 'admin/addshoes.html')


def editshoes(request, category, shoe_id):
    if 'admin' not in request.session:
        return redirect('login')

    if category == 'casual':
        shoe = get_object_or_404(Shoes, shoe_id=shoe_id)
    elif category == 'sports':
        shoe = get_object_or_404(Boots, boot_id=shoe_id)
    else:
        return redirect('adminshoes')

    if request.method == 'POST':
        shoe.name = request.POST.get('name')
        shoe.size = request.POST.get('size')
        shoe.quantity = request.POST.get('quantity')
        shoe.price = request.POST.get('price')
        shoe.description = request.POST.get('description')
        shoe.bestseller = request.POST.get('bestseller') == 'on'
        shoe.category = request.POST.get('category', category)
        if request.FILES.get('image'):
            shoe.image = request.FILES.get('image')
        shoe.save()
        messages.success(request, "Product updated.")
        return redirect('adminshoes')

    return render(request, 'admin/editshoes.html', {'shoe': shoe, 'category': category})


def delete_shoes(request, category, shoe_id):
    if category == 'casual':
        get_object_or_404(Shoes, shoe_id=shoe_id).delete()
    else:
        get_object_or_404(Boots, boot_id=shoe_id).delete()
    messages.success(request, "Deleted successfully.")
    return redirect('adminshoes')


def adminshoes(request):
    if 'admin' not in request.session: return redirect('login')
    search = request.GET.get('search', '').strip()
    casual = Shoes.objects.all().order_by('-shoe_id')
    sports = Boots.objects.all().order_by('-boot_id')
    if search:
        casual = casual.filter(Q(name__icontains=search) | Q(category__icontains=search))
        sports = sports.filter(Q(name__icontains=search) | Q(category__icontains=search))
    return render(request, 'admin/adminshoes.html',
                  {'casualshoes': casual, 'sportsshoes': sports, 'search_query': search})


def adminhome(request):
    if 'admin' not in request.session: return redirect('login')
    context = {
        'total_orders': OrderDetails.objects.count(),
        'total_products': Shoes.objects.count() + Boots.objects.count(),
        'total_users': UserDetails.objects.count(),
        'pending_orders': OrderDetails.objects.filter(status='pending').count(),
    }
    return render(request, 'admin/adminhome.html', context)


def userdetails(request):
    return render(request, 'admin/userdetails.html', {'users': UserDetails.objects.all()})


def orderdetails(request, order_id):
    order = get_object_or_404(OrderDetails, pk=order_id)
    items = MyOrders.objects.filter(order=order)
    if request.method == 'POST':
        order.status = request.POST.get('status')
        order.status_note = request.POST.get('note')
        order.save()
        messages.success(request, 'Status updated.')
        return redirect('admin_order_detail', order_id=order_id)
    return render(request, 'admin/order_detail.html', {'order': order, 'items': items})


def admin_manage_orders(request):
    if 'admin' not in request.session: return redirect('login')
    orders = OrderDetails.objects.all().order_by('-created_at')
    status = request.GET.get('status')
    if status: orders = orders.filter(status=status)
    paginator = Paginator(orders, 20)
    return render(request, 'admin/manage_orders.html', {'page_obj': paginator.get_page(request.GET.get('page'))})


# --- Public Views ---

def indexed(request): return render(request, 'index.html')


def collection(request): return render(request, 'collection.html',
                                       {'shoes': Shoes.objects.all().order_by('-shoe_id')[:2]})


def contact(request): return render(request, 'contact.html', {'store': ContactUs.objects.first()})


def sports(request): return render(request, 'racing boots.html',
                                   {'boots': Boots.objects.all().order_by('-boot_id')[:6]})


def all_boots(request): return render(request, 'all_boots.html', {'boots': Boots.objects.all().order_by('-boot_id')})


def shoes(request): return render(request, 'shoes.html',
                                  {'shoes': Shoes.objects.all().order_by('-shoe_id')[:6], 'product_type': 'shoes'})


def all_shoes(request): return render(request, 'all_shoes.html', {'shoes': Shoes.objects.all().order_by('-shoe_id')})


def profile(request): return render(request, 'profile.html')


def myorder(request): return render(request, 'myorder.html')


def search(request):
    query = request.GET.get('query', '')
    return render(request, 'search.html', {
        'query': query,
        'shoes_results': Shoes.objects.filter(name__icontains=query),
        'boots_results': Boots.objects.filter(name__icontains=query)
    })


# --- Cart & Wishlist Logic ---

@csrf_exempt
@require_POST
def add_to_cart_v2(request, product_type, product_id):
    """Unified add to cart logic"""
    try:
        quantity = int(request.POST.get('quantity', 1))
        size = request.POST.get('size', '').strip()
        if not size: return JsonResponse({'error': 'Please select a size'}, status=400)

        # Get Product
        if product_type in ['shoe', 'shoes']:
            product = Shoes.objects.get(shoe_id=product_id)
            model_class = 'shoe'
        elif product_type in ['boot', 'boots']:
            product = Boots.objects.get(boot_id=product_id)
            model_class = 'boot'
        else:
            return JsonResponse({'error': 'Invalid product type'}, status=400)

        if product.quantity < quantity:
            return JsonResponse({'error': 'Insufficient stock'}, status=400)

        # Logged in User
        if 'userid' in request.session:
            user = UserDetails.objects.get(userid=request.session['userid'])
            cart_item, created = Cart.objects.get_or_create(
                user_details=user,
                itemid=str(product_id),
                size=size,
                product_type=model_class,
                defaults={'price': product.price, 'quantity': 0, 'image': product.image}
            )
            if cart_item.quantity + quantity > product.quantity:
                return JsonResponse({'error': 'Exceeds stock limits'}, status=400)

            cart_item.quantity += quantity
            cart_item.save()
            return JsonResponse({'success': True, 'message': 'Added to cart'})

        # Guest User
        else:
            guest_cart = request.session.get('guest_cart', [])
            for item in guest_cart:
                if (str(item.get('itemid')) == str(product_id) and
                        item.get('product_type') == model_class and
                        item.get('size') == size):
                    if item['quantity'] + quantity > product.quantity:
                        return JsonResponse({'error': 'Exceeds stock limits'}, status=400)
                    item['quantity'] += quantity
                    request.session['guest_cart'] = guest_cart
                    return JsonResponse({'success': True, 'message': 'Cart updated'})

            guest_cart.append({
                'itemid': str(product_id),
                'price': float(product.price),
                'quantity': quantity,
                'size': size,
                'image_url': product.image.url if product.image else '',
                'product_type': model_class,
                'name': product.name
            })
            request.session['guest_cart'] = guest_cart
            return JsonResponse({'success': True, 'message': 'Added to cart'})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_POST
def add_to_cart_from_wishlist(request, product_type, product_id):
    """Moves item from wishlist to cart"""
    # 1. Reuse existing add_to_cart logic
    response = add_to_cart_v2(request, product_type, product_id)
    response_data = json.loads(response.content)

    # 2. If successful, remove from wishlist
    if response.status_code == 200 and response_data.get('success'):
        try:
            # We need to find which wishlist item to remove
            # Since wishlist items might be guests or users, we use the remove logic
            # However, remove logic needs a specific ID (PK or string ID)
            # The frontend calls this via form, so we check if there's a specific wishlist_id passed
            # If not, we try to find it by product info

            if 'userid' in request.session:
                user = UserDetails.objects.get(userid=request.session['userid'])
                # Construct composite ID that was likely used in wishlist
                norm_type = 'shoe' if product_type in ['shoe', 'shoes'] else 'boot'
                composite_id = f"{norm_type}_{product_id}"
                Wishlist.objects.filter(user_details=user, itemid=composite_id).delete()
            else:
                # Guest remove
                norm_type = 'shoe' if product_type in ['shoe', 'shoes'] else 'boot'
                composite_id = f"{norm_type}_{product_id}"
                guest_wishlist = request.session.get('guest_wishlist', [])
                # Remove item that matches
                request.session['guest_wishlist'] = [i for i in guest_wishlist if i.get('itemid') != composite_id]
                request.session.modified = True

        except Exception as e:
            print(f"Error removing from wishlist after move: {e}")

    return response


@csrf_exempt
def remove_from_wishlist(request, wishlist_id):
    """Handles removing from wishlist for both DB PK (int) and Guest ID (str)"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid method'}, status=400)

    try:
        # Logged in User - wishlist_id is likely an integer PK
        if 'userid' in request.session:
            user = get_object_or_404(UserDetails, userid=request.session['userid'])
            # Since URL might pass a string like 'shoe_1' if the template logic was mixed up,
            # try to see if it's digit
            if str(wishlist_id).isdigit():
                Wishlist.objects.filter(pk=wishlist_id, user_details=user).delete()
            else:
                # If it's a string like 'shoe_1', delete by itemid
                Wishlist.objects.filter(itemid=str(wishlist_id), user_details=user).delete()

            return JsonResponse({'success': True, 'message': 'Removed from wishlist'})

        # Guest User - wishlist_id is 'shoe_1' etc.
        else:
            guest_wishlist = request.session.get('guest_wishlist', [])
            # Filter out the item
            new_list = [item for item in guest_wishlist if item.get('itemid') != str(wishlist_id)]
            request.session['guest_wishlist'] = new_list
            request.session.modified = True
            return JsonResponse({'success': True, 'message': 'Removed from wishlist'})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def add_to_wishlist(request, product_type, product_id):
    if request.method != 'POST': return JsonResponse({'error': 'POST required'}, status=400)
    try:
        if product_type in ['shoe', 'shoes']:
            product = get_object_or_404(Shoes, shoe_id=product_id)
            norm_type = 'shoe'
        else:
            product = get_object_or_404(Boots, boot_id=product_id)
            norm_type = 'boot'

        composite_id = f"{norm_type}_{product_id}"

        if 'userid' in request.session:
            user = UserDetails.objects.get(userid=request.session['userid'])
            if not Wishlist.objects.filter(user_details=user, itemid=composite_id).exists():
                Wishlist.objects.create(user_details=user, itemid=composite_id, price=product.price, size=product.size,
                                        image=product.image)
        else:
            guest_list = request.session.get('guest_wishlist', [])
            if not any(i['itemid'] == composite_id for i in guest_list):
                guest_list.append({
                    'itemid': composite_id, 'price': float(product.price),
                    'size': product.size, 'image_url': product.image.url,
                    'product_type': norm_type, 'name': product.name
                })
                request.session['guest_wishlist'] = guest_list
        return JsonResponse({'success': True, 'message': 'Added to wishlist'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def cart(request):
    """Cart view with Wishlist"""
    cart_items, wishlist_items = [], []
    total = 0

    if 'userid' in request.session:
        user = UserDetails.objects.get(userid=request.session['userid'])
        # Load Cart
        for c in Cart.objects.filter(user_details=user):
            try:
                prod = Shoes.objects.get(shoe_id=c.itemid) if c.product_type == 'shoe' else Boots.objects.get(
                    boot_id=c.itemid)
                sub = c.price * c.quantity
                total += sub
                cart_items.append({
                    'id': c.pk, 'name': prod.name, 'image_url': prod.image.url,
                    'price': prod.price, 'quantity': c.quantity, 'size': c.size,
                    'subtotal': sub, 'product_type': c.product_type, 'product_id': c.itemid
                })
            except:
                continue

        # Load Wishlist
        for w in Wishlist.objects.filter(user_details=user):
            ptype, pid, prod = parse_wishlist_itemid(w.itemid)
            if prod:
                wishlist_items.append({
                    'id': w.pk, 'name': prod.name, 'image_url': prod.image.url,
                    'price': prod.price, 'category': prod.category,
                    'product_type': ptype, 'product_id': pid
                })
    else:
        # Guest Cart
        guest_cart = request.session.get('guest_cart', [])
        for i in guest_cart:
            sub = i['price'] * i['quantity']
            total += sub
            cart_items.append({
                'id': i['itemid'], 'name': i['name'], 'image_url': i['image_url'],
                'price': i['price'], 'quantity': i['quantity'], 'size': i['size'],
                'subtotal': sub, 'product_type': i['product_type'], 'product_id': i['itemid']
            })

        # Guest Wishlist
        guest_wish = request.session.get('guest_wishlist', [])
        for i in guest_wish:
            wishlist_items.append({
                'id': i['itemid'], 'name': i['name'], 'image_url': i['image_url'],
                'price': i['price'], 'category': 'General',
                'product_type': i['product_type'], 'product_id': i['itemid'].split('_')[1]
            })

    return render(request, 'cart.html',
                  {'cart_items': cart_items, 'total_amount': total, 'wishlist_items': wishlist_items})


def wishlist(request):
    """Standalone wishlist view"""
    items = []
    if 'userid' in request.session:
        user = UserDetails.objects.get(userid=request.session['userid'])
        for w in Wishlist.objects.filter(user_details=user):
            ptype, pid, prod = parse_wishlist_itemid(w.itemid)
            if prod:
                items.append({
                    'id': w.pk, 'name': prod.name, 'image_url': prod.image.url,
                    'price': prod.price, 'category': prod.category,
                    'product_type': ptype, 'product_id': pid
                })
    else:
        for i in request.session.get('guest_wishlist', []):
            # Parse the itemid to extract numeric ID
            item_id_str = str(i['itemid'])
            if '_' in item_id_str:
                numeric_id = int(item_id_str.split('_')[1])
            else:
                numeric_id = int(item_id_str)

            items.append({
                'id': i['itemid'],  # Keep full ID for removal
                'name': i['name'],
                'imageurl': i['imageurl'],
                'price': i['price'],
                'category': 'General',
                'producttype': i['producttype'],
                'productid': numeric_id  # Use JUST the number
            })
    return render(request, 'wishlist.html', {'wishlist_items': items})


def update_cart_quantity(request, cart_id):
    if request.method != 'POST': return JsonResponse({'error': 'POST required'}, status=400)
    qty = int(request.POST.get('quantity', 1))

    if 'userid' in request.session:
        cart_item = get_object_or_404(Cart, pk=cart_id, user_details__userid=request.session['userid'])
        if qty > 0:
            cart_item.quantity = qty
            cart_item.save()
        else:
            cart_item.delete()

        # Recalculate total
        total = sum(i.price * i.quantity for i in Cart.objects.filter(user_details__userid=request.session['userid']))
        return JsonResponse({'success': True, 'cart_total': float(total), 'price': float(cart_item.price)})
    else:
        cart = request.session.get('guest_cart', [])
        total = 0
        item_price = 0
        for i, item in enumerate(cart):
            if str(item['itemid']) == str(cart_id):
                item_price = item['price']
                if qty > 0:
                    cart[i]['quantity'] = qty
                else:
                    del cart[i]
                break

        total = sum(i['price'] * i['quantity'] for i in cart)
        request.session['guest_cart'] = cart
        return JsonResponse({'success': True, 'cart_total': total, 'price': item_price})


def remove_from_cart(request, cart_id):
    if request.method != 'POST': return JsonResponse({'error': 'POST required'}, status=400)
    if 'userid' in request.session:
        Cart.objects.filter(pk=cart_id, user_details__userid=request.session['userid']).delete()
    else:
        cart = request.session.get('guest_cart', [])
        request.session['guest_cart'] = [i for i in cart if str(i['itemid']) != str(cart_id)]
    return JsonResponse({'success': True})


def checkout_page(request):
    if 'userid' not in request.session: return redirect('login')

    # Get payment method from GET params (passed from cart)
    payment_method = request.GET.get('payment_method', 'cod')  # Default to COD if not set

    user = UserDetails.objects.get(userid=request.session['userid'])
    cart_items = Cart.objects.filter(user_details=user)
    if not cart_items: return redirect('cart')

    total = sum(i.price * i.quantity for i in cart_items)
    display_items = []
    for c in cart_items:
        try:
            prod = Shoes.objects.get(shoe_id=c.itemid) if c.product_type == 'shoe' else Boots.objects.get(
                boot_id=c.itemid)
            display_items.append({
                'name': prod.name, 'image_url': prod.image.url,
                'price': c.price, 'quantity': c.quantity, 'size': c.size,
                'subtotal': c.price * c.quantity
            })
        except:
            continue

    context = {
        'cart_items': display_items,
        'total_price': total,
        'payment_method': payment_method,  # Pass to template
        'user': user
    }
    return render(request, 'checkout.html', context)


def payment(request):
    if 'userid' not in request.session: return redirect('login')
    if request.method == 'POST':
        total = float(request.POST.get('total_amount', 0))
        method = request.POST.get('payment_method', 'cod')
        address = request.POST.get('address')

        user = UserDetails.objects.get(userid=request.session['userid'])
        cart_items = Cart.objects.filter(user_details=user)

        order = OrderDetails.objects.create(
            user=user, username=user.name, useraddress=address,
            phnno=user.phoneno or '', pincode=user.pincode or '',
            status='pending'
        )

        items_list = []
        for c in cart_items:
            # Determine content type and object
            if c.product_type == 'shoe':
                ct = ContentType.objects.get_for_model(Shoes)
                prod = Shoes.objects.get(shoe_id=c.itemid)
            else:
                ct = ContentType.objects.get_for_model(Boots)
                prod = Boots.objects.get(boot_id=c.itemid)

            MyOrders.objects.create(
                order=order, content_type=ct, object_id=c.itemid,
                user_name=user.name, user_address=address,
                phno=user.phoneno or '', pincode=user.pincode or '',
                quantity=c.quantity, size=c.size, price=c.price
            )

            if prod.quantity >= c.quantity:
                prod.quantity -= c.quantity
                prod.save()

        if method == 'cod':
            order.status = 'confirmed'
            order.save()
            cart_items.delete()
            messages.success(request, "Order Placed Successfully!")
            return render(request, 'payment.html',
                          {'total_amount': total, 'payment_method': 'cod', 'order_id': order.orderid})
        elif method == 'razorpay':
            rz_order = razorpay_client.order.create(
                {'amount': int(total * 100), 'currency': 'INR', 'payment_capture': 1})
            request.session['pending_order_id'] = order.orderid
            return render(request, 'payment.html', {
                'razorpay_key': settings.RAZORPAY_KEY_ID, 'razorpay_amount': int(total * 100),
                'payment': rz_order, 'total_amount': total, 'payment_method': 'razorpay',
                'user': user, 'order_id': order.orderid
            })

    return redirect('checkout_page')


@csrf_exempt
def payment_success(request):
    if request.method == 'POST':
        order_id = request.POST.get('order_id')
        try:
            order = OrderDetails.objects.get(orderid=order_id)
            order.status = 'confirmed'
            order.save()
            if 'userid' in request.session:
                Cart.objects.filter(user_details__userid=request.session['userid']).delete()
            messages.success(request, "Payment Successful!")
            return redirect('myorder')
        except:
            return redirect('cart')
    return redirect('myorder')


def track_order(request):
    """Simple track order view"""
    if 'userid' not in request.session: return redirect('login')
    user = UserDetails.objects.get(userid=request.session['userid'])
    orders = OrderDetails.objects.filter(user=user).order_by('-created_at')
    return render(request, 'track_order.html', {'user_orders': orders})


def my_orders(request):
    """Same as track_order essentially"""
    return track_order(request)


# Admin extra views
def ad_collection(request): return render(request, 'admin/ADcollection.html', {'shoes': Shoes.objects.all()[:2]})


def ad_shoes(request): return render(request, 'admin/ADshoes.html', {'shoes': Shoes.objects.all()})


def ad_sports(request): return render(request, 'admin/ADracing boots.html', {'boots': Boots.objects.all()})


def ad_search(request): return render(request, 'admin/ADsearch.html')