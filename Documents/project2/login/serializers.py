from rest_framework import serializers
from login.models import Register,UserProfile,Vendor,Visitor
from login.models import Notice
from django.contrib.auth.models import User

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Register
        fields = ('id','username', 'phonenumber', 'password')

class NoticeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notice
        fields = ('id', 'notice_detail', 'posted_by', 'posted_on')

class RegisteredUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ('id','uname')

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id','username','password')

class VendorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = ('id','society_id','vendor_name','vendor_type','vendor_mobileno')

class VisitorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Visitor
        fields = ('id','flat_id','owner_name','visitor_name','visitor_mobile','otp','dateof_visit')
