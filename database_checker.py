# database_checker.py
# Place this file in your Django project root and run: python database_checker.py

import os
import django
import sqlite3

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bagyourshoe.settings')  # Replace with your project name
django.setup()

from django.db import connection


def check_database_schema():
    """Check if all required tables and columns exist"""

    with connection.cursor() as cursor:
        # Check if Cart table exists and get its schema
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='app_cart';")
        result = cursor.fetchone()

        if result:
            print("✓ app_cart table exists")
            print("Table schema:")
            print(result[0])
            print("\n" + "=" * 50 + "\n")

            # Check specifically for product_type column
            cursor.execute("PRAGMA table_info(app_cart);")
            columns = cursor.fetchall()

            print("Columns in app_cart table:")
            column_names = []
            for column in columns:
                column_names.append(column[1])
                print(f"  - {column[1]} ({column[2]})")

            if 'product_type' in column_names:
                print("\n✓ product_type column exists")
            else:
                print("\n✗ product_type column is MISSING!")

        else:
            print("✗ app_cart table does NOT exist")

        # Check other important tables
        important_tables = ['app_userdetails', 'app_shoes', 'app_boots', 'app_cart', 'app_wishlist']

        print(f"\n{'=' * 50}")
        print("Checking all important tables:")
        print(f"{'=' * 50}")

        for table in important_tables:
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}';")
            exists = cursor.fetchone()
            status = "✓" if exists else "✗"
            print(f"{status} {table}")


if __name__ == "__main__":
    try:
        check_database_schema()
    except Exception as e:
        print(f"Error: {e}")
        print("\nMake sure to:")
        print("1. Replace 'bagyourshoe' with your actual project name")
        print("2. Run this from your Django project root directory")
        print("3. Ensure your virtual environment is activated")