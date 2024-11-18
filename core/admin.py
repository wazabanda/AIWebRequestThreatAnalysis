from django.contrib import admin
from .models import RequestSuspicousLog,RequestRedirect,SuspicousIP
# Register your models here.

@admin.register(RequestRedirect)
class RedirectAdmin(admin.ModelAdmin):


@admin.register(RequestSuspicousLog)
class SuspicousLogAdmin(admin.ModelAdmin):
    list_display = ['']

@admin.register(SuspicousIP)
class IPAmdin(admin.ModelAdmin):
    list_display  = ['source_ip','time_identified','time_allowed','redirect']
