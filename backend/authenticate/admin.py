from django.contrib import admin
from .models import User
from django.contrib.auth.admin import UserAdmin
from django.utils.safestring import mark_safe


class UserAuthenticationAdmin(UserAdmin):
    list_display = ('id', 'username', 'email', 'first_name', 'last_name',
                    'is_admin', 'is_active', 'created_at', 'updated_at', 'last_login')

    list_filter = ('is_admin', 'is_active')

    fieldsets = (
        (None, {'fields': ('username', 'password', 'verification_OTP')}),
        ('Personal Info', {'fields': ('first_name',
         'last_name', 'email',)}),
        ('Permissions', {'fields': ('is_admin',
         'is_active', 'groups', 'user_permissions')}),
        ('Important Dates', {'fields': ["last_login"]})
    )
    exclude = ('ctreated_at', 'updated_at')

    filter_horizontal = ()


admin.site.register(User, UserAuthenticationAdmin)
