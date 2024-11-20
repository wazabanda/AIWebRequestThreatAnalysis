from django.db import models
from django.conf import Settings
from django.utils import choices, timezone
from django.core.exceptions import ValidationError
from pandas.core.algorithms import mode

# Create your models here.

class RequestRedirect(models.Model):
    name = models.CharField(max_length=32,blank=True)
    short_description = models.CharField(max_length=64,blank=True)
    source_route = models.CharField(max_length=64)
    good_redirect_route = models.CharField(max_length=255)
    bad_redirect_route = models.CharField(max_length=255)


    def __str__(self):
        return str(self.name)

# class RequestLog(models.Model):
#     source_ip = models.CharField(max_length=64)
#     destination = models.ForeignKey(RequestRedirect,on_delete=models.PROTECT)
#
#     timestamp = models.DateTimeField(default=timezone.now)
#
class SuspicousIP(models.Model):
    source_ip = models.CharField(max_length=64)
    time_identified = models.DateTimeField(default=timezone.now)
    time_allowed = models.DateTimeField(default=timezone.now)
    redirect = models.ForeignKey(to=RequestRedirect,on_delete=models.PROTECT)
    first_seen = models.DateTimeField(default=timezone.now)


    @property
    def associated_request_logs(self):
        return RequestLog.objects.filter(sus_ip=self)

    def __str__(self):
        return self.source_ip
    

class RequestLog(models.Model):

    METHODS = (("GET","GET"),("POST","POST"))
    REQ_TYPE = (("GOOD","GOOD"),("BAD","BAD"),("BAD_ENTRY","BAD_ENTRY"),("CHECK","CHECK"))
    source_ip = models.CharField(max_length=64)
    sus_ip = models.ForeignKey(to=SuspicousIP,on_delete=models.CASCADE,null=True,blank=True,related_name="request_logs")
    path = models.CharField(max_length=255,blank=True)
    body = models.TextField(blank=True)
    headers = models.JSONField(blank=True,null=True)
    method = models.CharField(max_length=10,choices=METHODS,blank=True)
    request_type = models.CharField(max_length=10,choices=REQ_TYPE,blank=True)
    timestamp = models.DateTimeField(default=timezone.now)
    redirect = models.ForeignKey(RequestRedirect,on_delete=models.PROTECT,null=True)
    response_body = models.TextField(blank=True)
    response_status_code = models.CharField(max_length=3,blank=True,null=True)

    def save(self, *args, **kwargs):
        if self.pk:  # If the model instance already exists
            raise ValidationError("This model is read-only and cannot be modified.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("This model is read-only and cannot be deleted.")

