from __future__ import unicode_literals
from rest_framework import status
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from rest_framework.decorators import api_view
from rest_framework.response import Response
from login.models import Register,UserProfile,Vendor,Visitor
from login.serializers import RegisterSerializer,RegisteredUserSerializer,UserSerializer,VendorSerializer,VisitorSerializer
from django.shortcuts import render
from django.contrib.auth import authenticate, login,logout
from django.contrib.auth.models import User
from login.forms import UserForm, UserProfileForm
from django.contrib.auth.decorators import login_required
#from djsms import send_text
from googlevoice import Voice
from googlevoice.util import input
import urllib.request
import http.cookiejar
import sys
from http.cookiejar import CookieJar
import urllib
import urllib.parse
from twilio.rest import TwilioRestClient
import random
from django.core.cache import cache



def signupPage(request):
    return render(request, 'signup.html')

def loginpage(request):
    return render(request, 'login.html')

def logincheck(request):
    return render(request, 'logincheck.html')

def logout_user(request):
    return render(request,'logout.html')


@api_view(['GET','POST'])
def registration(request):
    if request.method == 'POST':
        try:
           user_exists = User.objects.get(username=request.POST['username'])
           return Response("Username already taken")
        except User.DoesNotExist:
             uform = UserForm(data = request.POST)
             pform = UserProfileForm(data = request.POST)
             if  uform.is_valid() and pform.is_valid() :
                user = uform.save()
                pw = user.password
                user.set_password(pw)
                user.save()
                profile = pform.save(commit = False)
                profile.user = user
                profile.save()
                return Response('/register success')
             else:
                form = UserForm()
                return Response('in post')
 
    return Response(
    'register unsuccessful',
  
    )


@api_view(['GET', 'POST'])
def registereduser(request):
    """
    List all snippets, or create a new snippet.
    """
    if request.method == 'GET':
        #user = UserProfile.objects.all()
        user = User.objects.all()
        serializer = UserSerializer(user, many=True)
        return Response(serializer.data)
        #return Response('ione');

    elif request.method == 'POST':
        serializer = RegisterSerializer(data=request.data)
        try:
            if serializer.is_valid():
               user = Register.objects.get(phonenumber=request.data['phonenumber'])
               return Response('already register')
        except Register.DoesNotExist:
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'POST'])
def userregister(request):
    """
    List all snippets, or create a new snippet.
    """
    if request.method == 'GET':
        user = Register.objects.all()
        serializer = RegisterSerializer(user, many=True)
        return Response(serializer.data)
        #return Response('its done');

    elif request.method == 'POST':
        serializer = RegisterSerializer(data=request.data)
        try:
            if serializer.is_valid():
               user = Register.objects.get(phonenumber=request.data['phonenumber'])
               return Response('already register')
        except Register.DoesNotExist:
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'POST'])
def user_login(request):
    #context = RequestContext(request)
    if request.method == 'POST':
          username = request.POST['username']
          password = request.POST['password']
          user = authenticate(username=username, password=password)
          if user is not None:
              if user.is_active:
                  login(request, user)
                  return Response("allow for login")
              else:
                  # Return a 'disabled account' error message
                  return Response("You're account is disabled.")
          else:
              # Return an 'invalid login' error message.
              return Response('invalid login')
    else:
        # the login is a  GET request, so just show the user the login form.
        return Response('invalid')

@api_view(['GET', 'POST'])
def checkfor_loggedinuser(request):
        try:
            user = User.objects.get(username=request.POST['username'])
            if  request.user.is_authenticated() and user.is_active:
                   return Response('loggedin')
        except User.DoesNotExist:
             return Response(' not loggedin')
        return Response(' not loggedin')


@api_view(['GET','POST'])
def user_logout(request):
    #user = User.objects.get(username=request.POST['username'])
    logout(request)
    # Redirect back to index page.
    return Response('logout')



@api_view(['GET','POST'])
def vendor_list(request):
    vendor = Vendor.objects.all()
    serializer = VendorSerializer(vendor, many=True)
    s={"visitors":serializer.data}
    return Response(s)

@api_view(['GET','POST'])
def visitor(request):
    visitors = Visitor.objects.all()
    serializer = VisitorSerializer(visitors, many=True)
    s={"visitors":serializer.data}
    return Response(s)

@api_view(['GET','POST'])
def addnewvisitor(request):
    if request.method == 'POST':
       request.POST._mutable = True
       pin = get_pin()
       request.POST['otp']=pin
       serializer = VisitorSerializer(data=request.data)
       if serializer.is_valid():
          serializer.save()
          send_pin(pin)
          return Response(serializer.data, status=status.HTTP_201_CREATED)
       return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def get_pin(length=4):
    """ Return a numeric PIN with length digits """
    return random.sample(range(10**(length-1), 10**length), 1)[0]

def verify_pin(mobile_number, pin):
    return pin == cache.get(mobile_number)

#@api_view(['GET','POST'])
def send_pin(pin):
    """ Sends SMS PIN to the specified number """
    #mobile_number = request.POST.get('mobile_number', "")
    #if not mobile_number:
     #   return HttpResponse("No mobile number", mimetype='text/plain', status=403)
    mobile_number='+917207682115'
    #pin = get_pin()

    # store the PIN in the cache for later verification.
    #cache.set(mobile_number, pin, 24*3600) # valid for 24 hrs

    client = TwilioRestClient("AC45909f611138d83b2e7d8757723b4f3a","4e6c46dcb8a15ce8c8cf82ec95361727")
    message = client.messages.create(
                        body="just testing--sandy  your otp is:%s" % pin,
                        to=mobile_number,
                        from_="+12565308064",
                    )
    #return HttpResponse("Message %s sent" % message.sid, mimetype='text/plain', status=200)



@api_view(['GET', 'PUT', 'DELETE'])
def user_details(request, pk, format=None):
    """
    Retrieve, update or delete a snippet instance.
    """
    try:
        user = Register.objects.get(pk=pk)
    except Register.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = RegisterSerializer(user)
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = RegisterSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

  
def sms(request):
    username=  "8892652336"    #write ur mobile number for way2sms inside " " 
    passwd=   "1234"       #password for way2sms inside " "
 
    message="messge u want to send "
    number="+918892652336"
 
    message="+".join(message.split(' '))
 
    url= 'http://192.168.0.35:8000/login'
 
    data1 = 'username='+username+'&password='+passwd
   
    req = urllib.request.Request(url)
    cj =http.cookiejar.CookieJar()
    opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
 
    opener.addheaders=[('User-Agent',"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko)           Chrome/43.0.2357.134 Safari/537.36")]
 
 
    try:
        usock = opener.open(req,data)
    except IOError:
          sys.exit(1)
 
 
    jession_id = str(cj).split('~')[1].split(' ')[0]
    
    p= opener.open("http://site21.way2sms.com/ebrdg.action?id="+jession_id)
 
    send_sms_url='http://site21.way2sms.com/smstoss.action'
 
 
    send_sms_data= 'ssaction=ss&Token='+jession_id+'&mobile='+number+'&message='+message+'&msgLen='+str(140-len(message))
    opener.addheaders=[('Referer','http://site21.way2sms.com/sendSms?Token='+jession_id)]
 
    try:
        sms_sent_page = opener.open(send_sms_url,send_sms_data)
    except IOError as e :
       print 
 
    p=opener.open('http://site21.way2sms.com/smscofirm.action?SentMessage='+message+'&Token='+jession_id+'&status=0')




def sms2(request):
    username = None
    passwd = None
    message = None
    number = None
 
# Fill in stuff
    if username is None: username = input("8892652336 ")
    if passwd is None: passwd = input("8892652336")
    if message is None: message = input("Enter Message: ")
    if number is None: number = input("8892652336 ")
 
#Logging into the SMS Site
    url = 'http://site21.way2sms.com/content/index.html'
    d = 'username='+username+'&password='+passwd+'&Submit=Sign+in'
    params = urllib.parse.urlencode({'username': username, 'password': passwd})
    params = params.encode('utf-8')
    #data = urllib.parse.urlencode(d).encode("utf-8")
    #req = urllib.request.Request([('url', url)])
    #req = urllib.request.Request(url,data)
 
#Remember, Cookies are to be handled
    cj = http.cookiejar.CookieJar()
    opener =urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
 
 
 
# To fool way2sms as if a Web browser is visiting the site
    opener.addheaders = [('User-Agent','Mozilla/5.0 (X11; Linux i686; rv:2.0.1) Gecko/20100101 Firefox/4.0.1')]
    opener.addheaders = [('Referer','http://site24.way2sms.com/entry.jsp')]
 
 
 
 
    try:
       usock = opener.open(url,params)
    except IOError:
       #print "Check your internet connection"
       sys.exit(1)
 
 
#urlencode performed.. Because it was done by the site as i checked through HTTP headers
 
    while True:
         # message = urlencode({'message':message})
          message = message[message.find("=")+1:]
   
          #SMS sending
          send_sms_url = 'http://ver3.way2sms.com/FirstServletsms?custid='
          send_sms_data = 'custid=undefined&HiddenAction=instantsms&Action=455dasv556&login=&pass=&MobNo='+number +'&textArea='+message
          opener.addheaders = [('Referer', 'http://ver3.way2sms.com/jsp/InstantSMS.jsp?val=0')]
 
          try:
             sms_sent_page = opener.open(send_sms_url,send_sms_data)
          except IOError:
                #print "Check your internet connection( while sending sms)"
                sys.exit(1)
                #print "SMS sent!!!"
       
          message = raw_input("Enter Message: ")


@api_view(['GET','POST'])
def sms3(request):
   ACCOUNT_SID = "AC45909f611138d83b2e7d8757723b4f3a" 
   AUTH_TOKEN = "4e6c46dcb8a15ce8c8cf82ec95361727" 
 
   client = TwilioRestClient(ACCOUNT_SID, AUTH_TOKEN) 
 
   client.messages.create(
	to="+917207682115", 
	from_="+12565308064", 
	body="just testing--------sandy", ) 
    #print message.sid
