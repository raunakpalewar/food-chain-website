from django.db import models

from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    def _create_user(self,email,password,**extra_fields):
        if not email:
            return ValueError("Please Provide Proper Email Address")
        
        email=self.normalize_email(email)
        user=self.model(email=email,**extra_fields)
        user.set_password(password)
        user.save(using=self.db)
        return user
    
    def create_user(self,email=None,password=None,**extra_fields):
        extra_fields.setdefault('is_staff',False)
        extra_fields.setdefault('is_superuser',False)
        return self._create_user(email,password,**extra_fields)
    
    def create_superuser(self,email=None,password=None,**extra_fields):
        extra_fields.setdefault('is_staff',True)
        extra_fields.setdefault('is_superuser',True)
        return self._create_user(email,password,**extra_fields)
    


class UserRegistration(AbstractBaseUser,PermissionsMixin):
    USER_ROLE=(
        ('owner','OWNER'),
        ('customer','CUSTOMER'),
    )
    
    email=models.EmailField(unique=True)
    password=models.CharField(max_length=255)
    full_name=models.CharField(max_length=255,null=True,blank=True)
    number=models.IntegerField(null=True,blank=True)
    otp=models.IntegerField(null=True,blank=True)
    otp_created_at=models.DateTimeField(auto_now_add=True,null=True,blank=True)
    user_created_at=models.DateTimeField(auto_now_add=True,null=True,blank=True)
    is_staff=models.BooleanField(default=False)
    is_active=models.BooleanField(default=True)
    is_superuser=models.BooleanField(default=False)
    is_valid=models.BooleanField(default=False)
    is_verified=models.BooleanField(default=False)
    is_registered=models.BooleanField(default=False)
    number_verified=models.BooleanField(default=False)
    role=models.CharField(null=True,blank=True,choices=USER_ROLE,max_length=255)
    address = models.CharField(max_length=255,null=True,blank=True)
    city = models.CharField(max_length=100,null=True,blank=True)
    zip_code = models.CharField(max_length=20,null=True,blank=True)
    
    objects=CustomUserManager()
    
    USERNAME_FIELD='email'
    REQUIRED_FIELDS=[]
    
    def __str__(self):
        # return self.id
        return f"{self.email}-{self.role}"
    

class Restaurant(models.Model):
    owner=models.OneToOneField(UserRegistration,on_delete=models.CASCADE,null=True,blank=True)
    name = models.CharField(max_length=255)
    address = models.CharField(max_length=255)
    image=models.FileField(upload_to='medai/restraunt/',null=True,blank=True)

    def __str__(self):
        return self.name

class FoodCategory(models.Model):
    category=models.CharField(max_length=255)
    
    def __str__(self):
        return self.category
    
    def save(self, *args, **kwargs):
        # Save category name in lowercase
        self.category = self.category.lower()
        super(FoodCategory, self).save(*args, **kwargs)

class FoodItem(models.Model):
    
    restaurant = models.ForeignKey(Restaurant, on_delete=models.CASCADE, related_name='menu_items')
    food_name = models.CharField(max_length=255)
    image=models.FileField(upload_to='media/',null=True,blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    food_category=models.ForeignKey(FoodCategory,on_delete=models.CASCADE,related_name='foodcategory')


    def __str__(self):
        return self.food_name

class OrderItems(models.Model):
    user = models.ForeignKey(UserRegistration, on_delete=models.CASCADE, related_name='orders' ,null=True,blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    item_name=models.ManyToManyField(FoodItem, related_name='orders')
    quantity = models.PositiveIntegerField(default=1)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    location = models.CharField(null=True,blank=True,max_length=255)
    restaurant = models.ForeignKey('Restaurant', on_delete=models.CASCADE, related_name='order_history', null=True, blank=True)
