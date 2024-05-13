from .models import *
from rest_framework import serializers


class UserRegistrationsSerializer(serializers.ModelSerializer):
    class Meta:
        model=UserRegistration
        fields='__all__'

class FoodItemsSerializer(serializers.ModelSerializer):
    class Meta:
        model=FoodItem
        fields='__all__'

class RestrauntSerializer(serializers.ModelSerializer):
    menu_items = FoodItemsSerializer(many=True, read_only=True)

    class Meta:
        model=Restaurant
        fields='__all__'

class FoodCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model=FoodCategory
        fields='__all__'
        


# class UserAddressSerializer(serializers.ModelSerializer):
#     class Meta:
#         model=UserAddress
#         fields='__all__'
class OrderItemsSerializer(serializers.ModelSerializer):
    class Meta:
        model=OrderItems
        fields='__all__'

# class OrderDetailsSerializer(serializers.ModelSerializer):
#     class Meta:
#         model=OrderDetails
#         fields='__all__'