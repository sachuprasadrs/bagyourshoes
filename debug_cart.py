# debug_cart.py
# Place this file in your Django project root and run: python debug_cart.py

import os
import django

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bagyourshoe.settings')  # Replace with your actual project name
django.setup()

from app.models import Cart, UserDetails
from django.db import connection


def debug_cart_issue():
    """Debug the cart queryset issue"""

    print("=== Debugging Cart Issue ===\n")

    # Check if there's any data in the cart table
    cart_count = Cart.objects.count()
    print(f"Total cart items in database: {cart_count}")

    if cart_count > 0:
        print("\nCart items found. Let's examine them:")

        # Try to fetch cart items one by one to isolate the issue
        try:
            for i, cart_item in enumerate(Cart.objects.all(), 1):
                print(f"\nCart Item {i}:")
                print(f"  ID: {cart_item.id}")
                print(f"  Item ID: {cart_item.itemid}")
                print(f"  Product Type: {cart_item.product_type}")
                print(f"  Price: {cart_item.price}")
                print(f"  Quantity: {cart_item.quantity}")
                print(f"  Size: {cart_item.size}")
                print(f"  User: {cart_item.user_details}")

        except Exception as e:
            print(f"Error iterating through cart items: {e}")

            # Try raw SQL to see what's in the table
            print("\nTrying raw SQL query:")
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM app_cart LIMIT 5;")
                rows = cursor.fetchall()

                cursor.execute("PRAGMA table_info(app_cart);")
                columns = [col[1] for col in cursor.fetchall()]

                print(f"Columns: {columns}")
                print("Sample data:")
                for row in rows:
                    print(f"  {dict(zip(columns, row))}")

    else:
        print("No cart items found in database.")

    # Check for any specific user cart items
    print(f"\n=== Checking User Sessions ===")
    users = UserDetails.objects.all()[:5]
    for user in users:
        user_cart_count = Cart.objects.filter(user_details=user).count()
        print(f"User {user.name} (ID: {user.userid}): {user_cart_count} cart items")

    # Test a specific queryset that might be causing the issue
    print(f"\n=== Testing Specific Querysets ===")
    try:
        # This is similar to what your view is doing
        test_queryset = Cart.objects.filter(user_details__isnull=True)
        print(f"Anonymous cart items: {test_queryset.count()}")

        test_queryset2 = Cart.objects.all()
        print(f"All cart items (using .all()): {test_queryset2.count()}")

        # Try to iterate (this is where the error occurs in your view)
        print("Testing iteration...")
        for item in test_queryset2[:1]:  # Just test first item
            print(f"Successfully accessed item: {item.id}")

    except Exception as e:
        print(f"Error in queryset testing: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    try:
        debug_cart_issue()
    except Exception as e:
        print(f"Setup error: {e}")
        print("Make sure to update the project name in DJANGO_SETTINGS_MODULE")