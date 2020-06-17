from django.shortcuts import render, HttpResponse, redirect
import requests
import json
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from .utils import generate_token
from django.core.mail import EmailMessage


# Create your views here.

def index(request):
    if request.method == 'REDIRECT':
        return HttpResponse('logged in')

    return render(request, 'recap/index.html')


def signup(request):
    if request.method == 'POST':
        # ====recaptcha
        clientkey = request.POST['g-recaptcha-response']
        secretKey = '6LdodKUZAAAAAEUvYcGtGy48Zc3hj6AZt6P7nUVx'
        captchaData = {
            'secret': secretKey,
            'response': clientkey
        }
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=captchaData)
        response = json.loads(r.text)
        verify = response['success']

        if verify:
            mail = request.POST.get('email', '')
            userCheck = User.objects.filter(email=mail)
            if userCheck:
                messages.error(request, 'Email already exist')
                return redirect('/signuppage')

            first_name = request.POST.get('first_name', '')
            last_name = request.POST.get('last_name', '')
            phone = request.POST.get('phone', '')
            password = request.POST.get('password', '')
            conf_pass = request.POST.get('confirm_password', '')
            usernm = mail.split('@')

            if password == conf_pass:
                user_obj = User.objects.create_user(first_name=first_name, last_name=last_name, password=password,
                                                    email=mail, username=mail, phone=phone)
                user_obj.is_active = False
                current_site = get_current_site(request)
                email_sub = "Activate your account"
                message = render_to_string('recap/activate.html',
                                           {
                                               'user': user_obj,
                                               'domain': current_site.domain,
                                               'uid': urlsafe_base64_encode(force_bytes(user_obj.pk)),
                                               'token': generate_token.make_token(user_obj),
                                           })
                email = EmailMessage(
                    email_sub,
                    message,
                    settings.EMAIL_HOST_USER,
                    [mail]
                )
                try:
                    email.send()

                except:
                    messages.error(request, "Email address do not exist")
                    return redirect('/signuppage')

                user_obj.save()


            else:
                messages.error(request, "Passwords don't match")
                return redirect('/signuppage')
        else:
            messages.error(request, "Enter the Captcha")
            return redirect('/signuppage')

    return render(request, 'recap/postSignUp.html', {'email':usernm[1]})


def user_login(request):
    if request.method == 'POST':
        # ====recaptcha
        clientkey = request.POST['g-recaptcha-response']
        secretKey = '6LdodKUZAAAAAEUvYcGtGy48Zc3hj6AZt6P7nUVx'
        captchaData = {
            'secret': secretKey,
            'response': clientkey
        }
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=captchaData)
        response = json.loads(r.text)
        verify = response['success']

        if verify:
            mail = request.POST.get('email', '')
            user_password = request.POST.get('pass', '')
            usernm = mail.split('@')

            user = authenticate(username=mail, password=user_password, email=mail)

            if user is not None and user.is_active:
                login(request, user)
                messages.success(request, "Logged in")
                return redirect('/userpage/' + str(user.pk))

            else:
                messages.error(request, "No user exists with that credentials")
                return redirect('/')
        else:
            messages.error(request, "Enter the reCaptcha")
            return redirect('/')


def userPage(request, id):
    user = User.objects.get(pk=id)
    return render(request, 'recap/postLogin.html', {'user': user})


def user_logout(request):
    logout(request)
    messages.success(request, 'Logged out')
    return redirect('/')


def activateView(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)

    except:
        user = None
    if user is not None and generate_token.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Account activated successfully')
        return redirect('/')
    else:
        messages.error(request, 'Couldnt activate your account')
