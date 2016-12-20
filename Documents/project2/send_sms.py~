from twilio.rest import TwilioRestClient
from twilio import TwilioRestException
account_sid = "{{ AC45909f611138d83b2e7d8757723b4f3a }}" # Your Account SID from www.twilio.com/console
auth_token  = "{{4e6c46dcb8a15ce8c8cf82ec95361727 }}"  # Your Auth Token from www.twilio.com/console

client = TwilioRestClient(account_sid, auth_token)
try:
    message = client.messages.create(body="Hello from sandy",
          to="+918892652336",    # Replace with your phone number
          from_="+12565308064") # Replace with your Twilio number
except TwilioRestException as e:
    print(e)
