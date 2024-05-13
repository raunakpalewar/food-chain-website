from django.shortcuts import render, redirect
from django.http import HttpResponse
import requests
from django.http import HttpResponseRedirect
from decimal import Decimal  # Import Decimal for accurate decimal arithmetic
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import *
from .models import *
from django.contrib.auth.hashers import make_password, check_password
import re
from django.contrib.auth import login, logout
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAuthenticatedOrReadOnly, IsAdminUser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import random
from django.conf import settings
from django.core.mail import send_mail
from datetime import timedelta
from .pagination import CustomPageNumberPagination
from django.db.models import Q



BASE_URL='http://0.0.0.0:8005/'

def generate_otp():
    return str(random.randint(100000, 999999))


def send_otp_email(email, otp):
    subject = 'OTP for user Registration '
    message = f'your otp for Registration is :  {otp}'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)


def get_token_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token)
    }


class CustomerRegistration(APIView):
    @swagger_auto_schema(
        operation_description="This if for Customer Registration",
        operation_summary="Customer can Register using this api",
        tags=['OAuth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
                'number': openapi.Schema(type=openapi.TYPE_INTEGER),
                'address': openapi.Schema(type=openapi.TYPE_STRING),
                'city': openapi.Schema(type=openapi.TYPE_STRING),
                'zip_code': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
            requried=['email', 'password', 'name',
                      'number', 'address', 'city', 'zip_code']
        ),
    )
    def post(self, request):
        try:
            data = request.data
            try:
                email = data.get('email')
                password = data.get('password')
                name = data.get('name')
                number = data.get('number')
                address = data.get('address')
                city = data.get('city')
                zip_code = data.get('zip_code')

                def password_validate(password):
                    if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(){}[\]:;,<>\'\"~])[A-Za-z\d!@#$%^&*(){}[\]:;,<>\'\"~]{8,16}$', password):
                        raise ValueError(
                            "Password must be 8 to 16 characters long with one uppercase, one lowercase, a number, and a special character.")
                email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

                if not email or not re.match(email_regex, email):
                    return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Invalid email format"}, status=status.HTTP_400_BAD_REQUEST)
                if not password:
                    return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Password is required."}, status=status.HTTP_400_BAD_REQUEST)

                try:
                    password_validate(password)
                except Exception as e:
                    return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                otp = generate_otp()
                print(otp)
                send_otp_email(email, otp)
                user_password = make_password(password)
                user = UserRegistration.objects.create(email=email, number=number, password=user_password,
                                                       otp=otp, role='customer', full_name=name, address=address, city=city, zip_code=zip_code)
                user.otp_created_at = timezone.now()
                user.user_created_at = timezone.now()
                user.is_registered = True
                user.save()
                return Response({'message': 'user registered successfully'}, status=status.HTTP_201_CREATED)
            except:
                return Response({"status": status.HTTP_400_BAD_REQUEST, 'message': 'could not register user try again'}, status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': 'could not register user try again'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class Restraunt_owner_Registration(APIView):
    @swagger_auto_schema(
        operation_description="This if for Restraunt Registration",
        operation_summary="Restraunt Owner can Register using this api",
        tags=['OAuth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
                'number': openapi.Schema(type=openapi.TYPE_INTEGER),
                'address': openapi.Schema(type=openapi.TYPE_STRING),
                'city': openapi.Schema(type=openapi.TYPE_STRING),
                'zip_code': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
            requried=['email', 'password', 'name',
                      'number', 'address', 'city', 'zip_code']
        ),
    )
    def post(self, request):
        try:
            data = request.data
            try:
                email = data.get('email')
                password = data.get('password')
                name = data.get('name')
                number = data.get('number')
                address = data.get('address')
                city = data.get('city')
                zip_code = data.get('zip_code')

                def password_validate(password):
                    if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(){}[\]:;,<>\'\"~])[A-Za-z\d!@#$%^&*(){}[\]:;,<>\'\"~]{8,16}$', password):
                        raise ValueError(
                            "Password must be 8 to 16 characters long with one uppercase, one lowercase, a number, and a special character.")
                email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

                if not email or not re.match(email_regex, email):
                    return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Invalid email format"}, status=status.HTTP_400_BAD_REQUEST)
                if not password:
                    return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Password is required."}, status=status.HTTP_400_BAD_REQUEST)

                try:
                    password_validate(password)
                except Exception as e:
                    return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                otp = generate_otp()
                send_otp_email(email, otp)
                user_password = make_password(password)
                user = UserRegistration.objects.create(email=email, number=number, password=user_password,
                                                       otp=otp, role='owner', full_name=name, address=address, city=city, zip_code=zip_code)
                user.otp_created_at = timezone.now()
                user.user_created_at = timezone.now()
                user.is_registered = True
                user.save()
                return Response({'message': 'user registered successfully'}, status=status.HTTP_201_CREATED)
            except:
                return Response({"status": status.HTTP_400_BAD_REQUEST, 'message': 'could not register user try again'}, status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': 'could not register user try again'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyEmail(APIView):
    @swagger_auto_schema(
        operation_description='Verify you email',
        operation_summary='user has to verify his/her email using the otp sended within 3 minutes',
        tags=['OAuth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'otp': openapi.Schema(type=openapi.TYPE_NUMBER)
            },
        ),
    )
    def post(self, request):
        data = request.data
        email = data.get('email')
        otp = data.get('otp')

        try:
            user = UserRegistration.objects.get(email=email)
            time_difference = timezone.now()-user.otp_created_at
            if time_difference <= timedelta(minutes=3):
                if otp == user.otp:
                    user.is_valid = True
                    user.is_verified = True
                    user.save()
                    return Response({'status': status.HTTP_200_OK, 'message': "User Verified Successfully"}, status=status.HTTP_200_OK)
                return Response({'status': status.HTTP_400_BAD_REQUEST, "message": "Invalid OTP"}, status.HTTP_400_BAD_REQUEST)
            else:
                otp = generate_otp()
                send_otp_email(email, otp)
                user.otp = otp
                user.otp_created_at = timezone.now()
                user.save()
                return Response({'status': status.HTTP_400_BAD_REQUEST, "message": "time out for  OTP \n new opt sended \n try again using new otp"}, status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status': status.HTTP_404_NOT_FOUND, "message": "User not found"}, status.HTTP_404_NOT_FOUND)


class Login(APIView):
    @swagger_auto_schema(
        operation_description="login here",
        operation_summary='login to you account',
        tags=['OAuth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email', 'password'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
    )
    def post(self, request):
        try:
            data = request.data

            email = data.get('email')
            password = data.get('password')

            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not email or not re.match(email_regex, email):
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Invalid email format"}, status=status.HTTP_400_BAD_REQUEST)
            if not password:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Password is required."}, status=status.HTTP_400_BAD_REQUEST)

            user = UserRegistration.objects.get(
                email=email, is_verified=True, is_registered=True)

            try:
                if check_password(password, user.password):
                    try:
                        login(request, user)
                        token = get_token_for_user(user)
                        # serializer=UserRegistrationsSerializer(user)
                        return Response({"status": status.HTTP_200_OK, 'message': 'Login successfully', 'token': token, "Your user id": user.id, 'You_are': user.role}, status=status.HTTP_200_OK)
                    except Exception as e:
                        return Response({"messsage": f"user not verified please verify you email first using otp {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({"status": status.HTTP_400_BAD_REQUEST, 'message': "invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({"status": status.HTTP_400_BAD_REQUEST, 'message': 'user not found', "error_message": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserLogout(APIView):
    def get(self, request):
        logout(request)
        return Response({"status": status.HTTP_200_OK, 'message': 'logout successfully done'}, status.HTTP_200_OK)


class ForgotPassword(APIView):
    @swagger_auto_schema(
        operation_description="Forgot Password",
        operation_summary="Reset Your password using new otp",
        tags=['OAuth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING)
            },
        ),
    )
    def post(self, request):
        try:
            data = request.data
            email = data.get('email')
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not email:
                return Response({'message': 'Email id is required.'}, status=status.HTTP_400_BAD_REQUEST)
            if not re.match(email_regex, email):
                return Response({'message': 'Please enter a valid email address.'}, status=status.HTTP_400_BAD_REQUEST)
            try:
                user = UserRegistration.objects.get(email=email)
                otp = generate_otp()
                send_otp_email(email, otp)
                user.otp = otp
                user.otp_created_at = timezone.now()
                user.save()
                return Response({'message': 'OTP sent successfully for password reset.'}, status=status.HTTP_200_OK)

            except UserRegistration.DoesNotExist:
                return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except UserRegistration.DoesNotExist:
            return Response({'message': 'User not found.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SetNewPassword(APIView):
    @swagger_auto_schema(
        operation_description='Set New Password',
        operation_summary='Please Enter you new password',
        tags=['OAuth'],

        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'otp': openapi.Schema(type=openapi.TYPE_NUMBER),
                'new_password': openapi.Schema(type=openapi.TYPE_STRING),
                'confirm_password': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
    )
    def post(self, request):
        try:
            data = request.data
            email = data.get('email')
            data['email'] = email

            otp = data.get('otp')
            password = data.get('new_password')
            cpassword = data.get('confirm_password')

            if not password:
                return Response({"message": "Please enter a new password"}, status=status.HTTP_400_BAD_REQUEST)
            if password != cpassword:
                return Response({"message": "New password and Confirm password must be the same."}, status=status.HTTP_400_BAD_REQUEST)

            password_regex = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$'
            if not re.match(password_regex, password):
                return Response({"message": "Invalid password format"}, status=status.HTTP_403_FORBIDDEN)

            try:
                user = UserRegistration.objects.get(email=email)
                time_difference = timezone.now()-user.otp_created_at
                if time_difference <= timedelta(minutes=3):
                    if otp == user.otp:
                        user.set_password(password)
                        user.save()
                        return Response({'status': status.HTTP_200_OK, 'message': "Password Changed Successfully"}, status=status.HTTP_200_OK)
                    return Response({'status': status.HTTP_400_BAD_REQUEST, "message": "Invalid OTP"}, status.HTTP_400_BAD_REQUEST)
                else:
                    otp = generate_otp()
                    send_otp_email(email, otp)
                    user.otp = otp
                    user.otp_created_at = timezone.now()
                    user.save()
                    return Response({'status': status.HTTP_400_BAD_REQUEST, "message": "time out for  OTP \n new opt sended \n try again using new otp"}, status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'status': status.HTTP_404_NOT_FOUND, "message": f"User not found {str(e)}"}, status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, "message": f"User not found {str(e)}"}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class RegisterRestaurant(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Register a new restaurant",
        operation_summary="Register a new restaurant in the system",
        tags=['Restaurant'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER,
                              type=openapi.TYPE_STRING)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'address': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
        responses={
            status.HTTP_201_CREATED: "Restaurant registered successfully",
            status.HTTP_400_BAD_REQUEST: "Invalid data provided",
        }
    )
    def post(self, request):
        try:
            authuser = request.user
            print(authuser)
            if authuser.role == 'owner':

                data = request.data
                data['owner'] = authuser.id
                # data['image']=request.FILES.get('image')

                serializer = RestrauntSerializer(data=request.data)
                if serializer.is_valid():
                    image = request.data.get('image')
                    serializer.save(image=image)                    
                    return Response("Restaurant registered successfully", status=status.HTTP_201_CREATED)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"response": "unauthorised access"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'Response': str(e), "status": "Internal Server error"}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class AddRestaurantMenu(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Add menu items for a restaurant",
        operation_summary="Add menu items to an existing restaurant",
        tags=['Restaurant'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER,
                              type=openapi.TYPE_STRING)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'food_name': openapi.Schema(type=openapi.TYPE_STRING),
                'price': openapi.Schema(type=openapi.TYPE_INTEGER),
                'type': openapi.Schema(type=openapi.TYPE_STRING)
            },
        ),
        responses={
            status.HTTP_201_CREATED: "Menu items added successfully",
            status.HTTP_400_BAD_REQUEST: "Invalid data provided",
        }
    )
    def post(self, request):
        try:
            data = request.data
            authuser = request.user
            if authuser.role == 'owner':
                data['restaurant'] = authuser.id
                restaurant_instance = Restaurant.objects.get(owner=authuser)
                restaurant_id = restaurant_instance.id

                print(authuser.id)
                # restaurant_id = authuser.id

                food_category_name = data.get('type')
                food_category = FoodCategory.objects.get(
                    category=food_category_name)
                data['food_category'] = food_category.id
                data['restaurant'] = restaurant_id
                serializer = FoodItemsSerializer(data=request.data)
                if serializer.is_valid():
                    # serializer.save()
                    image = request.data.get('image')
                    if image:
                        serializer.save(image=image)
                    serializer.save()

                    return Response("Menu items added successfully", status=status.HTTP_201_CREATED)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"response": "unauthorised access"}, status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"Response": f"internal server error {str(e)}", "status": status.HTTP_401_UNAUTHORIZED}, status.HTTP_401_UNAUTHORIZED)



class UpdateRestaurantMenuItem(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update menu item for a restaurant",
        operation_summary="Update an existing menu item in a restaurant",
        tags=['Restaurant'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER,
                              type=openapi.TYPE_STRING),
            openapi.Parameter('food_name', openapi.IN_QUERY,
                              description="Name of the food item", type=openapi.TYPE_STRING)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'price': openapi.Schema(type=openapi.TYPE_INTEGER),
                'type': openapi.Schema(type=openapi.TYPE_STRING)
            },
        ),
        responses={
            status.HTTP_200_OK: "Menu item updated successfully",
            status.HTTP_400_BAD_REQUEST: "Invalid data provided",
            status.HTTP_404_NOT_FOUND: "Menu item not found",
            status.HTTP_401_UNAUTHORIZED: "Unauthorized access",
            status.HTTP_500_INTERNAL_SERVER_ERROR: "Internal server error"
        }
    )
    def put(self, request):
        try:
            authuser = request.user
            if authuser.role == 'owner':
                restaurant_instance = Restaurant.objects.get(owner=authuser)
                restaurant_id = restaurant_instance.id

                # restaurant_id = authuser.id
                food_name = request.query_params.get('food_name')
                food_category_name = request.data.get('type')

                if not food_name:
                    return Response("Food name parameter is required", status=status.HTTP_400_BAD_REQUEST)

                try:
                    menu_item = FoodItem.objects.get(
                        food_name=food_name, restaurant=restaurant_id)
                except FoodItem.DoesNotExist:
                    return Response("Menu item not found", status=status.HTTP_404_NOT_FOUND)

                if food_category_name:
                    food_category = FoodCategory.objects.get(
                        category=food_category_name)
                    menu_item.food_category = food_category

                menu_item.price = request.data.get('price')
                image=request.data.get('image')
                if image:
                    menu_item.image = image
                    menu_item.save()
                menu_item.save()
                return Response("Menu item updated successfully", status=status.HTTP_200_OK)
            else:
                return Response({"response": "Unauthorized access"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"Response": f"Internal server error {str(e)}", "status": status.HTTP_500_INTERNAL_SERVER_ERROR},
                            status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeleteRestaurantMenuItem(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Delete menu item for a restaurant by name",
        operation_summary="Delete an existing menu item from a restaurant by name",
        tags=['Restaurant'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER,
                              type=openapi.TYPE_STRING),
            openapi.Parameter('food_name', openapi.IN_QUERY,
                              type=openapi.TYPE_STRING),
        ],
        responses={
            status.HTTP_204_NO_CONTENT: "Menu item deleted successfully",
            status.HTTP_404_NOT_FOUND: "Menu item not found",
        }
    )
    def delete(self, request):
        try:
            authuser = request.user
            if authuser.role == 'owner':
                restaurant_id = authuser.id
                food_name = request.query_params.get('food_name', None)

                if food_name:
                    try:
                        menu_item = FoodItem.objects.get(
                            food_name=food_name, restaurant=restaurant_id)
                        menu_item.delete()
                        return Response("Menu item deleted successfully", status=status.HTTP_204_NO_CONTENT)
                    except FoodItem.DoesNotExist:
                        return Response("Menu item not found", status=status.HTTP_404_NOT_FOUND)
                else:
                    return Response("Invalid food name provided", status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"response": "unauthorized access"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"Response": f"internal server error {str(e)}", "status": status.HTTP_500_INTERNAL_SERVER_ERROR},
                            status.HTTP_500_INTERNAL_SERVER_ERROR)


class RetrieveRestaurantDetails(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve restaurant details",
        operation_summary="Retrieve details of the owner's restaurant",
        tags=['Restaurant'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER,
                              type=openapi.TYPE_STRING)
        ],
        responses={
            status.HTTP_200_OK: "Restaurant details retrieved successfully",
            status.HTTP_404_NOT_FOUND: "Restaurant not found",
        }
    )
    def get(self, request):
        try:
            authuser = request.user
            if authuser.role == 'owner':
                restaurant = Restaurant.objects.get(owner=authuser.id)
                serializer = RestrauntSerializer(restaurant)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response({"response": "unauthorized access"}, status=status.HTTP_401_UNAUTHORIZED)
        except Restaurant.DoesNotExist:
            return Response("Restaurant not found", status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"Response": f"internal server error {str(e)}", "status": status.HTTP_500_INTERNAL_SERVER_ERROR},
                            status.HTTP_500_INTERNAL_SERVER_ERROR)


class AddFoodCategory(APIView):
    @swagger_auto_schema(
        operation_description="Add a new food category",
        operation_summary="Add a new category for food items",
        tags=['Food'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'category': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
        responses={
            status.HTTP_201_CREATED: "Food category added successfully",
            status.HTTP_400_BAD_REQUEST: "Invalid data provided",
        }
    )
    def post(self, request):
        try:
            serializer = FoodCategorySerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response("Food category added successfully", status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Response": f"Iternal server errro {str(e)}", 'status': status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetAllFoodCategories(APIView):
    @swagger_auto_schema(
        operation_description="Get all food categories",
        operation_summary="Retrieve all existing food categories",
        tags=['Food'],
        responses={
            status.HTTP_200_OK: "List of all food categories",
            status.HTTP_500_INTERNAL_SERVER_ERROR: "Internal server error",
        }
    )
    def get(self, request):
        try:
            categories = FoodCategory.objects.all()
            serializer = FoodCategorySerializer(categories, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"Response": f"Internal server error {str(e)}"}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class OrderFood(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Place a food order",
        operation_summary="Place an order for food items",
        tags=['Order'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER,
                              type=openapi.TYPE_STRING)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={

                'item_name': openapi.Schema(type=openapi.TYPE_STRING),
                'quantity': openapi.Schema(type=openapi.TYPE_INTEGER),
                'location': openapi.Schema(type=openapi.TYPE_STRING),
            }
        ),
        responses={
            status.HTTP_201_CREATED: "Order placed successfully",
            status.HTTP_400_BAD_REQUEST: "Invalid data provided",
        }
    )
    def post(self, request):
        try:
            user = request.user
            if user.role == 'customer':
                data = request.data
                quantity = data.get('quantity')
                item_name = data.get('item_name')
                food = FoodItem.objects.get(food_name=item_name)
                price = food.price
                location = data.get('location')

                total_amount = price * Decimal(quantity)

                # Here, get the corresponding restaurant of the food item
                restaurant = food.restaurant

                # Create the order instance and add the food item to the Many-to-Many field
                order = OrderItems.objects.create(
                    user=user, quantity=quantity, amount=total_amount, location=location, restaurant=restaurant)
                # Add the food item to the Many-to-Many relationship
                order.item_name.add(food)

                response_data = {
                    # Wrap item_name in a list to make it a list of strings
                    'item_name': [item_name],
                    'quantity': quantity,
                    'price': price,
                    'location': location,
                    'total': total_amount
                }

                # Send emails to the owner and customer
                send_order_emails(user, restaurant, response_data)

                return Response(response_data, status=status.HTTP_201_CREATED)
            return Response({"message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return Response({"message": str(e), "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def send_order_emails(customer, restaurant, order_data):
    # Prepare email content
    # You can modify this content
    customer_email_content = f"Your order details: {order_data}"

    # Send email to customer
    send_mail('Order Confirmation', customer_email_content,
              settings.EMAIL_HOST_USER, [customer.email])

    # Prepare email content for the restaurant owner
    # You can modify this content
    owner_email_content = f"New order details: {order_data}"

    # Send email to the restaurant owner
    send_mail('New Order', owner_email_content,
              settings.EMAIL_HOST_USER, [restaurant.owner.email])


class AllRestaurantList(APIView):

    @swagger_auto_schema(
        operation_description="Get a list of all restaurants and their menu items",
        operation_summary="Retrieve all restaurants and their served food items",
        manual_parameters=[
            openapi.Parameter('restaurant_name', openapi.IN_QUERY,
                              type=openapi.TYPE_STRING, description="Restaurant Name"),
            openapi.Parameter('food_name', openapi.IN_QUERY,
                              type=openapi.TYPE_STRING, description="Food Name"),
            openapi.Parameter('location', openapi.IN_QUERY,
                              type=openapi.TYPE_STRING, description="Location")
        ],
        responses={
            status.HTTP_200_OK: "List of restaurants and their menu items",
            status.HTTP_400_BAD_REQUEST: "Bad request",
            status.HTTP_401_UNAUTHORIZED: "Unauthorized"
        }
    )
    def get(self, request):
        restaurant_name = request.GET.get('restaurant_name')
        food_name = request.GET.get('food_name')
        location = request.GET.get('location')

        # Create a Q object to build complex queries
        query = Q()

        # Check if each parameter has a value before adding it to the query
        if restaurant_name:
            query |= Q(name__icontains=restaurant_name)

        if food_name:
            query |= Q(menu_items__food_name__icontains=food_name)

        if location:
            query |= Q(address__icontains=location)

        if query:
            # Apply the constructed query to filter the data
            restaurants = Restaurant.objects.filter(query).distinct()
        else:
            # If no search parameter is provided, return all restaurants without filtering
            restaurants = Restaurant.objects.all()

        serialized_data = RestrauntSerializer(restaurants, many=True).data
        return Response(serialized_data, status=status.HTTP_200_OK)


# Create your views here.
def view1(request):
    api_url = f'{BASE_URL}AllRestaurantList'

    response = requests.get(api_url)

    if response.status_code == 200:
        restaurant_data = response.json()
        return render(request, 'index.html', {'restaurants': restaurant_data})
    return render(request, 'index.html')


# def opt(request):

#     account_sid = 'AC853ba44b2807cd9facda796877e0b3cd'
#     auth_token = 'ad7a4c5368b599aaf667de370da6783b'
#     client = Client(account_sid, auth_token)

#     message = client.messages.create(
#         from_='+15075851472',
#         body='your otp for registration is',
#         to='+919145433778'
#     )

#     print(message.sid)


def show_restaurants(request):
    if request.method == 'POST':
        # Assuming you have form fields with the names 'restaurant_name', 'food_name', and 'location'
        restaurant_name = request.POST.get('restaurant_name')
        food_name = request.POST.get('food_name')
        location = request.POST.get('location')

        api_url = f'{BASE_URL}AllRestaurantList'
        params = {
            'restaurant_name': restaurant_name,
            'food_name': food_name,
            'location': location
        }

        response = requests.get(api_url, params=params)

        if response.status_code == 200:
            restaurant_data = response.json()
            return render(request, 'index.html', {'restaurants': restaurant_data})
        else:
            error_message = "Failed to fetch restaurant data."
            return render(request, 'index.html', {'error_message': error_message})
    else:
        # If it's not a POST request (i.e., the user is loading the page for the first time)
        return render(request, 'index.html')


def home(request):
    return render(request, "home.html")


def loginpage(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        response = requests.post(f'{BASE_URL}Login', data={'email': email, 'password': password})

        if response.status_code == 200:
            response_data = response.json()
            print(response_data)

            access_token = response_data['token']['access']
            user_type = response_data['You_are']
            print(access_token)
            request.session['access_token'] = access_token
            print("access token", access_token)
            if user_type == 'customer':
                return redirect('view1')
            else:
                return redirect('restrauntmenu')
        else:
            # Login failed; show an error message
            return render(request, 'login.html', {"error_message": 'Invalid credentials. Please try again.'})

    return render(request, 'login.html')


def signup(request):
    if request.method == 'POST':
        data = {
            'email': request.POST.get('email'),
            'name': request.POST.get('name'),
            'password': request.POST.get('password'),
            'number': request.POST.get('number'),
            'address': request.POST.get('address'),
            'city': request.POST.get('city'),
            'zip_code': request.POST.get('zip_code'),
        }
        role = request.POST.get('role')

        if role == 'customer':
            response = requests.post(f'{BASE_URL}customerRegistration', data=data)
            print(response)
            if response.status_code == 201:
                return render(request, 'emailverify.html', {'response': data})
            else:
                return render(request, 'signup.html', {"error_message": 'User registration failed. Please try again.'})
        elif role == 'owner':
            response = requests.post(f'{BASE_URL}Restraunt_owner_Registration', data=data)
            print(response)
            if response.status_code == 201:
                return render(request, 'emailverify.html', {'response': data})
            else:
                return render(request, 'signup.html', {"error_message": 'User registration failed. Please try again.'})
    return render(request, 'signup.html')


def emailverify(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        otp = request.POST.get('otp')
        data={'email':email,
              'otp':otp}

        response = requests.post(f'{BASE_URL}VerifyEmail', data=data)

        if response.status_code == 200:

            return render(request, 'login.html')
        else:
            return render(request, 'emailverify.html', {"error_message": 'Invalid credentials. Please try again.'})

    return render(request, 'login.html')


def orderfood(request):
    if request.method == 'POST':
        access_token = request.session.get('access_token')
        if access_token:
            item_name = request.POST.get('item_name')
            quantity = request.POST.get('quantity'),
            location = request.POST.get('address')

            api_url = f'{BASE_URL}OrderFood'
            headers = {
                'Authorization': 'Bearer ' + access_token
            }
            data = {
                'item_name': item_name,
                'quantity': quantity,
                'location': location,
            }
            print(data)
            try:
                response = requests.post(api_url, data=data, headers=headers)
                print(response.status_code)

                if response.status_code == 201:
                    order_details = response.json()
                    print(order_details)
                    return render(request, 'order_success.html', {'order_details': order_details})
                else:
                    print(response.content)
                    error_message = "Failed to place the order. Please try again."
                    return render(request, 'order.html', {'error_message': error_message, 'item_name': item_name})
            except Exception as e:
                print(str(e))  
                error_message = "An error occurred while placing the order."
                return render(request, 'order.html', {'error_message': error_message, 'item_name': item_name})
        else:
            return render(request, 'login.html', {"error_message": 'Please login to place an order.'})
    else:
        return render(request, 'order.html')


def restrauntmenu(request):
    # Get the token from the session
    token = request.session.get('access_token')

    # Check if the token is present in the session
    if token:
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(f'{BASE_URL}particularrestaurantmenu/', headers=headers)

        if response.status_code == 200:
            restaurant_data = response.json()
            menu_items = restaurant_data.get('menu_items', [])
            restaurant_name = restaurant_data.get('name', '')
            restaurant_address = restaurant_data.get('address', '')
            restaurant_image = restaurant_data.get('image', '')

            # Pass menu items and restaurant details to the template
            return render(request, 'restraunt.html', {
                'menu_items': menu_items,
                'restaurant_name': restaurant_name,
                'restaurant_address': restaurant_address,
                'restaurant_image': restaurant_image
            })
        else:
            return render(request, 'restraunt.html', {'error_message': 'Failed to fetch restaurant menu data'})
    else:

        return render(request, 'login.html')


def set_new_password(request):
    if request.method == 'POST':
        endpoint = f'{BASE_URL}SetNewPassword'
        email = request.POST.get('email')
        otp = request.POST.get('otp')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        data = {
            'email': email,
            'otp': otp,
            'new_password': new_password,
            'confirm_password': confirm_password
        }

        response = requests.post(f'{BASE_URL}SetNewPassword', json=data)
        print(response.json())

        if response.status_code == 200:
            return render(request, 'login.html')
        elif response.status_code == 400:
            return render(request, 'forgotpassword.html')
        elif response.status_code == 403:
            return render(request, 'setnewpassword.html')
        else:
            return render(request, 'login.html')

    return render(request, 'setnewpassword.html')


def forgot_password(request):
    if request.method == 'POST':
        endpoint = f'{BASE_URL}ForgotPassword'

        email = request.POST.get('email')
        data = {"email": email}

        response = requests.post(endpoint, json=data)

        if response.status_code == 200:
            return render(request, 'setnewpassword.html')
        elif response.status_code == 400:
            return render(request, 'login.html')
        elif response.status_code == 404:
            return render(request, 'login.html')
        else:
            return render(request, 'login.html')
    return render(request, 'forgotpassword.html')


def add_new_restaurant(request):
    if request.method == 'POST':
        token = request.session.get('access_token')
        if token:
            headers = {'Authorization': f'Bearer {token}'}

            name = request.POST.get('name')
            address = request.POST.get('address')
            image = request.FILES['image'] 

            if name and address:
                payload = {
                    'name': name,
                    'address': address
                }
                files = {'image': image}  # Files for image upload

                response = requests.post(f'{BASE_URL}RegisterRestaurant', headers=headers, data=payload, files=files)
                print(response)

                if response.status_code == 201:
                    return redirect('restrauntmenu')
                else:
                    return render(request, 'add_restaurant.html', {'error_message': 'Failed to register restaurant'})

            return render(request, 'add_restaurant.html', {'error_message': 'Please provide all necessary details to register a restaurant'})
        else:
            return render(request, 'add_restaurant.html', {'error_message': 'Failed to authenticate user'})
    return render(request, 'add_restaurant.html')


def addmenu(request):
    if request.method == 'POST':
        token = request.session.get('access_token')
        if token:
            headers = {'Authorization': f'Bearer {token}'}

            food_name = request.POST.get('food_name')
            price = request.POST.get('price')
            food_type = request.POST.get('type')
            image = request.FILES.get('image')

            if food_name and price and food_type and image:
                payload = {
                    'food_name': food_name,
                    'price': price,
                    'type': food_type
                }

                # Use `files` in the request to send the image
                files = {'image': image}

                response = requests.post(f'{BASE_URL}AddRestaurantMenu', headers=headers, data=payload, files=files)
                print(response)
                if response.status_code == 201:
                    return redirect('restrauntmenu')

                else:
                    return render(request, 'addmenu.html', {'error_message': 'Failed to add menu item'})

            return render(request, 'addmenu.html', {'error_message': 'Please provide all necessary details to add a menu item'})
        else:
            return render(request, 'addmenu.html', {'error_message': 'Failed to authenticate user'})
    else:
        return render(request, 'addmenu.html')


def updatemenu(request):
    if request.method == 'POST':
        token = request.session.get('access_token')
        if token:
            food_name = request.POST.get('food_name')
            price = request.POST.get('price')
            food_type = request.POST.get('type')
            image = request.FILES.get('image')

            if image:
                files = {'image': image}
            else:
                files = None

            # image = request.FILES['image'] 

            if food_name and price and food_type:
                payload = {
                    'price': price,
                    'type': food_type,
                }

                update_url = f'{BASE_URL}updatemenu/?food_name={food_name}'
                headers = {'Authorization': f'Bearer {token}'}
                # files = {'image': image}  # Files for image upload
                response = requests.put(update_url, headers=headers, data=payload, files=files)
                print(response)

                if response.status_code == 200:
                    # Successful update, redirect to the restaurant menu page
                    return redirect('restrauntmenu')
                else:
                    # Display an error message if update failed
                    return redirect('restrauntmenu')
            else:
                # Display an error if any parameter is missing
                return redirect('restrauntmenu')
        else:
            # If no token is found, redirect to a page to handle authentication/login
            return render(request, 'updatemenu.html')

    return render(request, 'updatemenu.html')


def deletemenu(request):
    token = request.session.get('access_token')

    if token:
        headers = {'Authorization': f'Bearer {token}'}
        food_name = request.GET.get('food_name')

        if food_name:
            # Constructing the URL with the food_name as a query parameter
            delete_url = f'{BASE_URL}Deletemenuitem/?food_name={food_name}'

            # Sending a DELETE request to the constructed URL
            response = requests.delete(delete_url, headers=headers)

            # Checking the response for a successful deletion
            if response.status_code == 204:
                print(response)
                # Redirecting to the restaurant menu page upon successful deletion
                return redirect('restrauntmenu')
            else:
                # Handling deletion failure by redirecting back to the restaurant menu page
                return redirect('restrauntmenu')
        else:
            # Food name not provided, redirect to the restaurant menu page
            return redirect('restrauntmenu')
    else:
        # No access token found, render the restaurant menu page or redirect to login page
        return render(request, 'restraunt.html')


def user_logout(request):
    endpoint = f'{BASE_URL}user-logout'  # Replace with the correct URL
    response = requests.get(endpoint)

    if response.status_code == 200:
        # return render(request, "login.html")
        return redirect('home_page')
    else:
        return render(request,'home.html')
    
def owner_logout(request):
    endpoint = f'{BASE_URL}user-logout'  # Replace with the correct URL
    response = requests.get(endpoint)

    if response.status_code == 200:
        # return render(request, "login.html")
        return render(request,'home.html')
    else:
        return render(request,'home.html')
