# Settings that are pre-defined
import os

EMAIL_SENDER = 'no-reply@covidscholar.org'
ANNOTATE_INVITATION_SUBJECT = 'CovidScholar.org is inviting you to help with our annotation tasks'
ANNOTATE_INVITATION_SUBJECT_BODY = None
ANNOTATE_INVITATION_SUBJECT_HTML = '''<p>Dear {name},</p>
<p>
    CovidScholar.org invites you to work on some text annotation tasks to help us improve NLP models in fight
    of the current COVID pandemic.
</p>
<p>
    Here is your <b>personal</b> annotation link: <a href="{link}">{link}</a>. Please do not share it with anyone else.
    If you know someone who would also like to help improve our machine learning models, please have them request their
    own personal annotation link at:
    <a href="https://forms.gle/zHPQAdivXRHNBwrD8">https://forms.gle/zHPQAdivXRHNBwrD8</a>
</p>
<p>
    Best regards,
    <br/>
    CovidScholar.org
</p>
'''

# Settings to be defined

SERVER_NAME = 'annotation.covidscholar.org' # Just the hostname, nothing else, such as "annotation.covidscholar.org"
PREFERRED_URL_SCHEME = 'https'

MONGO_HOSTNAME = '' or os.environ['MONGO_HOSTNAME']
MONGO_DB = '' or os.environ['MONGO_DB']
MONGO_USERNAME = '' or os.environ['MONGO_USERNAME']
MONGO_PASSWORD = '' or os.environ['MONGO_PASSWORD']
MONGO_AUTHENTICATION_DB = '' or os.environ['MONGO_AUTHENTICATION_DB']

MAILGUN_API_ENDPOINT = 'https://api.mailgun.net/v3/DOMAIN'
MAILGUN_API_KEY = '' or os.environ['MAILGUN_API_KEY']

SECURITY_KEY = '' or os.environ['SECURITY_KEY'] # Some random strings
SECURITY_PASSWORD_SALT = '' or os.environ['SECURITY_PASSWORD_SALT'] # Some random strings
