import io
import qrcode
import pyotp
import qrcode.image.svg
from django.contrib.auth import login as auth_login, logout as auth_logout, authenticate
from django.shortcuts import redirect
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from authApp.models import UserModel
# Create your views here.

def signup_view(request):

    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        
        if not username or not email or not password:
            messages.error(request, "Veuillez remplir tous les champs.")
            return render(request, 'signup.html')
            
        if password != confirm_password:
            messages.error(request, "Les mots de passe ne correspondent pas.")
            return render(request, 'signup.html')
            
        if UserModel.objects.filter(email=email).exists():
            messages.error(request, "Un utilisateur avec cet email existe déjà.")
            return render(request, 'signup.html')
            
        if UserModel.objects.filter(username=username).exists():
            messages.error(request, "Ce nom d'utilisateur est déjà pris.")
            return render(request, 'signup.html')
            
        try:
            user = UserModel.objects.create_user(email=email, username=username, password=password)
            messages.success(request, "Inscription réussie ! Vous pouvez maintenant vous connecter.")
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f"Une erreur est survenue : {str(e)}")
            return render(request, 'signup.html')
            
    return render(request, 'signup.html')



def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
        
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        if not email or not password:
            messages.error(request, "Veuillez saisir votre email et votre mot de passe.")
            return render(request, 'login.html')
            
        user = authenticate(request, email=email, password=password)
        
        if user is not None:
            # if user.is2fa:
            #     # Store the authenticated user's ID in session
            #     request.session['pre_2fa_user_id'] = user.id
            #     return redirect('verify_totp')
            # else:
                # Log in fully and redirect to dashboard
            auth_login(request, user)
            messages.success(request, f"Bienvenue, {user.username} !")
            return redirect('dashboard')
        else:
            messages.error(request, "Email ou mot de passe incorrect.")
            
    return render(request, 'login.html')

@login_required(login_url="login")
def dashboard_view(request):
    if not request.user.is_authenticated:
        return render(request, 'authentication/totp_flow.html', {
            'initial_secret': '',
            'is_landing': True,
        })
        
    # Simulated logs for recent activity
    recent_activity = [
        {'type': 'Connexion', 'description': 'Connexion réussie', 'time': 'Aujourd\'hui', 'icon': 'login'},
        {'type': 'Sécurité', 'description': '2FA configuré' if request.user.is2fa else 'Aucune protection 2FA', 'time': 'Aujourd\'hui', 'icon': 'shield'},
        {'type': 'Compte', 'description': 'Création du compte', 'time': 'Récemment', 'icon': 'user'},
    ]
    return render(request, 'dashboard.html', {
        'recent_activity': recent_activity
    })



@login_required(login_url="login")
def disable_2fa(request):
    user = request.user

    if request.method != "POST":
        return redirect("dashboard")

    if not user.is2fa:
        messages.info(request, "La 2FA est déjà désactivée.")
        return redirect("dashboard")

    code = request.POST.get("code", "").strip()

    if not code or len(code) != 6 or not code.isdigit():
        messages.error(request, "Veuillez saisir un code à 6 chiffres.")
        return redirect("dashboard")

    totp = pyotp.TOTP(user.totp_key)

    if not totp.verify(code):
        messages.error(request, "Code de vérification incorrect.")
        return redirect("dashboard")

    user.is2fa = False
    user.save(update_fields=["is2fa"])

    messages.success(request, "La 2FA a été désactivée avec succès.")
    return redirect("dashboard")


@login_required(login_url= "login")
def logout(request) :
    request.session.pop('temp_totp_secret', None)
    auth_logout(request)
    messages.success(request, "Vous avez été déconnecté avec succès.")
    return redirect('login')

def verify_totp (request):
   pass

@login_required(login_url="login")
def setup_2fa (request):
    pass


def totp_flow_view(request):
    initial_secret = request.GET.get('secret', pyotp.random_base32())
    
    return render(request, 'totp_flow.html', {
        'initial_secret': initial_secret,
        'is_landing': False,
    })

    