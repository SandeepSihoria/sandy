from django.db import models
from datetime import date
from datetime import datetime
from django.contrib.auth.models import User
from django.forms import ModelForm
from django import forms
from django.utils import timezone

class UserProfile(models.Model):
        user = models.OneToOneField(User)
        # These fields are optional
        uname = models.CharField(max_length=100,blank=True)

        def __str__(self):
                return self.user.username



class Register(models.Model):
    username = models.CharField(max_length=100,blank=True)
    phonenumber = models.CharField(max_length=100)
    password= models.CharField(max_length=1000)
    #gmailid = models.CharField(max_length=100)
   


    def __str__(self):
        return self.username

class Notice(models.Model):
    notice_detail = models.CharField(max_length=100)
    posted_by= models.CharField(max_length=1000)
    posted_on = models.DateTimeField(default=datetime.now, blank=True)

    def __str__(self):
        return self.notice_detail


class Vendor(models.Model):
    society_id = models.CharField(max_length=100)
    vendor_name= models.CharField(max_length=1000)
    vendor_type= models.CharField(max_length=1000)
    vendor_mobileno = models.CharField(max_length=1000)

    def __str__(self):
        return self.society_id


class Society(models.Model):
    society_id = models.CharField(max_length=100)
    name= models.CharField(max_length=1000)
    address= models.CharField(max_length=1000)
    noOfFlats = models.CharField(max_length=10)
    city = models.CharField(max_length=100)
    secratoryName= models.CharField(max_length=100)
    def __str__(self):
        return self.society_id

class Visitor(models.Model):
    flat_id = models.CharField(max_length=10)
    owner_name = models.CharField(max_length=100)
    visitor_name= models.CharField(max_length=100)
    visitor_mobile= models.CharField(max_length=100)
    otp= models.CharField(max_length=100)
    dateof_visit= models.DateTimeField(default=timezone.now(),blank=True)
    

    def __str__(self):
        return self.flat_id



