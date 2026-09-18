from django.db import models
from django.contrib.auth.models import AbstractUser,BaseUserManager
# Create your models here.


class UserManagerService(BaseUserManager):
    def create_user(self, email,username, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email must be set')
        if not username:
            raise ValueError('The Username must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self.db)
        return user
    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        # Protections recommandées contre les mauvaises manipulations
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self.create_user(email,username, password, **extra_fields)

class UserModel(AbstractUser):
    email = models.EmailField(unique=True,null=False,blank=False)
    is2fa = models.BooleanField(default=False)
    totp_key = models.CharField(max_length=255, blank=True, null=True)
    objects = UserManagerService()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username','password']

    def __str__(self):
        return self.username

    
    
   