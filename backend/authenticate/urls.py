from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import *


urlpatterns = [
    path('register/', RegisterViews.as_view(), name='regiter'),
    path('verify/<str:otp>/', VerifyEmailView.as_view(), name='verify'),
    path('login/', LoginViews.as_view(), name='login'),
    path('profile/', UserProfileViews.as_view(), name='profile'),
    path('logout/', LogoutViews.as_view(), name='logout'),
    path('refresh_token/', TokenRefreshView.as_view()),
]
