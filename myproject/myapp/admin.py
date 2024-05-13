from django.contrib import admin
from .models import *
# Register your models here.


admin.site.register(UserRegistration)
admin.site.register(Restaurant)
admin.site.register(FoodItem)
admin.site.register(FoodCategory)
admin.site.register(OrderItems)
# admin.site.register(OrderDetails)