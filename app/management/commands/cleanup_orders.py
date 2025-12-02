from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from app.models import OrderDetails

class Command(BaseCommand):
    help = 'Cleanup pending orders older than 24 hours'

    def handle(self, *args, **kwargs):
        cutoff = timezone.now() - timedelta(hours=24)
        old_orders = OrderDetails.objects.filter(status='pending', created_at__lt=cutoff)
        count = old_orders.count()
        old_orders.delete()
        self.stdout.write(self.style.SUCCESS(f'Deleted {count} old pending orders'))
