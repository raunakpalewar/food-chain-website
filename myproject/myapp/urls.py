from django.urls import path
from django.conf.urls.static import static
from django.conf import settings
from .import views
from django.urls import re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from .import views

schema_view = get_schema_view(
   openapi.Info(
      title="Food Delivery website",
      default_version='r1',
      description="for 2 types of users (OWNER / CUSTOMER )",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('customerRegistration',views.CustomerRegistration.as_view()),
    path('Restraunt_owner_Registration',views.Restraunt_owner_Registration.as_view()),
    path('VerifyEmail',views.VerifyEmail.as_view()),
    path('Login',views.Login.as_view()),
    path('UserLogout',views.UserLogout.as_view()),
    path('ForgotPassword',views.ForgotPassword.as_view()),
    path('SetNewPassword',views.SetNewPassword.as_view()),
    path('RegisterRestaurant',views.RegisterRestaurant.as_view()),
    path('AddRestaurantMenu',views.AddRestaurantMenu.as_view()),
    path('AddFoodCategory',views.AddFoodCategory.as_view()),
    path('OrderFood',views.OrderFood.as_view()),
    path('AllRestaurantList',views.AllRestaurantList.as_view()),
    path('showrestraunts/',views.show_restaurants,name='showrestraunt'),
    path('loginpage/',views.loginpage,name='login_page'),
    path('home/',views.home,name="home_page"),
    path('signuppage/',views.signup,name='signuppage'),
    path('email_verify_page/',views.emailverify,name='verifyemaipage'),
    path('order_food.html',views.orderfood,name='order-food'),
    path('updatemenu/',views.UpdateRestaurantMenuItem.as_view()),
    path('Deletemenuitem/',views.DeleteRestaurantMenuItem.as_view()),
    path('particularrestaurantmenu/',views.RetrieveRestaurantDetails.as_view()),
    path('restrauntmenu/',views.restrauntmenu,name='restrauntmenu'),
    path('getallcategory/',views.GetAllFoodCategories.as_view()),
    path('view1/',views.view1,name='view1'),
    path('add_new_restaurant',views.add_new_restaurant,name='add_new_restaurant'),
    path('addmenu',views.addmenu,name='addmenu'),
    path('updatemenu',views.updatemenu,name='updatemenu'),
    path('deletemenu',views.deletemenu,name='deletemenu'),
    path('set_new_password',views.set_new_password,name='set_new_password'),
    path('forgot_password',views.forgot_password,name='forgot_password'),
    path('user_logout',views.user_logout,name='user_logout'),
    path('owner_logout',views.owner_logout,name='owner_logout')

]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)