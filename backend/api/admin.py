from django.contrib import admin

from .models import AuditLog, SignatureLog, UserProfile


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "role")
    list_filter = ("role",)
    search_fields = ("user__username",)
    raw_id_fields = ("user",)


@admin.register(SignatureLog)
class SignatureLogAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "action", "status", "timestamp", "data_hash")
    list_filter = ("action", "status")
    search_fields = ("user__username", "data_hash", "hash_hex")
    raw_id_fields = ("user",)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "action", "status", "timestamp", "data_hash")
    list_filter = ("action", "status")
    search_fields = ("user__username", "data_hash", "failure_reason")
    raw_id_fields = ("user",)
