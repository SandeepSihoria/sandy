from django.forms import ModelForm
from login.models import Register
from django import forms
from django.contrib.auth.models import User
from login.models import UserProfile

class UserForm(forms.ModelForm):
        class Meta:
                model = User
                fields = ["username","password"]

class UserProfileForm(forms.ModelForm):
        class Meta:
                model = UserProfile
                fields = ["uname"]
  
