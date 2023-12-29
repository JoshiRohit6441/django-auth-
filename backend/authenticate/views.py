from .models import *
from .serializer import RegisterUserSerializer, UserProfileSerializer
# LoginUserSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.decorators import APIView

from django.middleware import csrf
from rest_framework import decorators, permissions as rest_permissions
from rest_framework_simplejwt import tokens
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings


def get_user_token(user):
    refresh = tokens.RefreshToken.for_user(user)
    return {
        'refresh_token': str(refresh),
        'access_token': str(refresh.access_token),
    }


@decorators.permission_classes([])
class RegisterViews(APIView):
    def post(self, request):
        serializer = RegisterUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)


@decorators.permission_classes([])
class LoginViews(APIView):
    def post(self, request):

        username = request.data.get('username')
        password = request.data.get('password')

        user = User.objects.filter(username=username).first()

        if user is None:
            raise AuthenticationFailed("User not found")

        if not user.check_password(password):
            raise AuthenticationFailed("Incorrect Password")

        response = Response()
        tokens = get_user_token(user)

        response.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=tokens["access_token"],
            expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )
        response.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
            value=tokens["refresh_token"],
            expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )

        response.data = {
            'token': tokens,
            # 'user_id': user.id,
            'message': 'login successful'
        }
        response['X-CSRFToken'] = csrf.get_token(request)

        return response


@decorators.permission_classes([rest_permissions.IsAuthenticated])
class UserProfileViews(APIView):
    def get(self, request):
        refresh_token = request.COOKIES.get(
            settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH']
        )

        if refresh_token is None:
            raise AuthenticationFailed("UnAuthenticated")

        try:
            refresh_token = RefreshToken(refresh_token)
            refresh_token.verify()
            payload = refresh_token.payload
        except:
            raise AuthenticationFailed('invalid refresh token')

        user_id = payload.get('user_id')

        user = User.objects.filter(id=user_id).first()

        serializer = UserProfileSerializer(user)

        return Response(serializer.data, status=status.HTTP_200_OK)


@decorators.permission_classes([rest_permissions.IsAuthenticated])
class LogoutViews(APIView):
    def post(self, request):
        response = Response()
        refresh_token = request.COOKIES.get(
            settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH']
        )
        token = tokens.RefreshToken(refresh_token)
        token.blacklist()
        response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
        response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        response.delete_cookie('X-CSRFToken')
        response.delete_cookie('csrftoken')

        response['X-SCRFToken'] = None
        response.data = {
            "message": "user logout successfully"
        }
        return response
