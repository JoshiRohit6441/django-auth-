from typing import Any, Dict
from rest_framework import serializers
from .models import *


class RegisterUserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(
        style={"input_type": "password"}, write_only=True)

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name',
                  'last_name', 'password', 'password2')
        extra_kwargs = {
            'password': {'write_only': True},
            'password2': {'write_only': True},
        }

    def save(self, validated_data):
        validated_data.pop('verification_OTP', None)

        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            is_admin=False,
            is_active=False
        )

        password = validated_data['password']
        password2 = validated_data['password2']

        if password != password2:
            raise serializers.ValidationError(
                {'password': 'Passwords do not match!'})

        user.set_password(password)

        user.verification_OTP = generate_otp()
        user.save()

        return user


def generate_otp():
    return 12345


# class RegisterUserSerializer(serializers.ModelSerializer):
#     password2 = serializers.CharField(
#         style={"input_type": "password"}, write_only=True)

#     class Meta:
#         model = User
#         fields = ('username', "email", "first_name",
#                   "last_name", "password", "password2")
#         extra_kwargs = {
#             'password': {"write_only": True},
#             'password2': {"write_only": True},
#         }

#     def validate(self, data):
#         if data['password'] != data['password2']:
#             return serializers.ValidationError("password does not match")
#         return data

#     def create(self, validated_data):
#         validated_data.pop('password2')
#         user = User.objects.create_user(
#             username=validated_data['username'],
#             email=validated_data['email'],
#             first_name=validated_data['first_name'],
#             last_name=validated_data['last_name'],
#             password=validated_data['password'],
#             is_admin=False,
#             is_active=False
#         )
#         # user.save()

#         return user


# class LoginUserSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ('username', 'password')


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name',)
