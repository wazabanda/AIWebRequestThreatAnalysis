from django.db import models
from django.conf import Settings
from django.utils import timezone
from django.core.exceptions import ValidationError

# Create your models here.

class RequestRedirect(models.Model):
    source_route = models.CharField(max_length=64)
    good_redirect_route = models.CharField(max_length=255)
    bad_redirect_route = models.CharField(max_length=255)


class SuspicousIP(models.Model):
    source_ip = models.CharField(max_length=64)
    time_identified = models.DateTimeField(default=timezone.now)
    time_allowed = models.DateTimeField(default=timezone.now)
    redirect = models.ForeignKey(to=RequestRedirect,on_delete=models.PROTECT)


class RequestSuspicousLog(models.Model):

    METHODS = (("GET","GET"),("POST","POST"))
    suspicous_IP = models.ForeignKey(to=SuspicousIP,on_delete=models.PROTECT)
    destination_route = models.CharField(max_length=255)
    body = models.TextField()
    method = models.CharField(max_length=10,choices=METHODS)
    timestamp = models.DateTimeField(default=timezone.now)
        
    def save(self, *args, **kwargs):
        if self.pk:  # If the model instance already exists
            raise ValidationError("This model is read-only and cannot be modified.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("This model is read-only and cannot be deleted.")

