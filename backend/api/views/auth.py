"""Authentication views: register, login, logout, key management."""
from __future__ import annotations

import time

from django.contrib.auth import authenticate, get_user_model
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from ..crypto_utils import mock_timestamp_token
from ..key_utils import ensure_user_profile
from ..serializers import LoginSerializer, RegisterSerializer


@api_view(["POST"])
@permission_classes([AllowAny])
def register(request):
    serializer = RegisterSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    username = serializer.validated_data["username"].strip()
    password = serializer.validated_data["password"]
    signature_algorithm = serializer.validated_data.get("signature_algorithm") or "RSA-SHA256"
    if not username:
        return Response(
            {"detail": "Username is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    User = get_user_model()
    if User.objects.filter(username__iexact=username).exists():
        return Response(
            {"detail": "That username is already taken."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    user = User.objects.create_user(username=username, password=password)
    profile = ensure_user_profile(user, preferred_algorithm=signature_algorithm)
    token, _ = Token.objects.get_or_create(user=user)
    return Response(
        {
            "token": token.key,
            "username": user.username,
            "role": profile.role,
            "signature_algorithm": profile.signature_algorithm,
        },
        status=status.HTTP_201_CREATED,
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    username = serializer.validated_data["username"].strip()
    password = serializer.validated_data["password"]
    user = authenticate(request, username=username, password=password)
    if user is None:
        return Response(
            {"detail": "Invalid username or password."},
            status=status.HTTP_401_UNAUTHORIZED,
        )
    profile = ensure_user_profile(user)
    token, _ = Token.objects.get_or_create(user=user)
    return Response(
        {
            "token": token.key,
            "username": user.username,
            "role": profile.role,
            "signature_algorithm": profile.signature_algorithm,
        }
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    Token.objects.filter(user=request.user).delete()
    return Response({"detail": "Logged out."})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def my_public_key(request):
    try:
        profile = ensure_user_profile(request.user)
        # Return user's self-signed certificate (PEM). Never expose private keys.
        certificate_pem = (profile.certificate or "").strip() or (profile.certificate_pem or "").strip()
        response_data = {
            "username": request.user.username,
            "role": profile.role,
            "certificate": certificate_pem,
            "signature_algorithm": profile.signature_algorithm,
        }
        return Response(response_data)
    except Exception as e:
        return Response(
            {
                "status": "failed",
                "message": str(e),
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def set_signature_algorithm(request):
    algorithm = str(request.data.get("signature_algorithm", "")).strip()
    if algorithm not in {"RSA-SHA256", "ECDSA-P256-SHA256"}:
        return Response(
            {"detail": "signature_algorithm must be RSA-SHA256 or ECDSA-P256-SHA256."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    profile = ensure_user_profile(request.user, preferred_algorithm=algorithm)
    return Response(
        {
            "status": "success",
            "username": request.user.username,
            "signature_algorithm": profile.signature_algorithm,
            "message": "Signing algorithm updated.",
        }
    )


@api_view(["GET"])
@permission_classes([AllowAny])
def supported_algorithms(request):
    return Response(
        {
            "algorithms": [
                {"id": "RSA-SHA256", "label": "RSA-SHA256"},
                {"id": "ECDSA-P256-SHA256", "label": "ECDSA-P256-SHA256"},
            ]
        }
    )


@api_view(["GET"])
def timestamp(request):
    """Mock Timestamp Authority endpoint."""
    token = mock_timestamp_token()
    return Response({
        "timestamp_token": token,
        "ts_unix": int(time.time())
    })
