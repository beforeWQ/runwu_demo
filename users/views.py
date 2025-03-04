from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .serializers import UserSerializer, UserDetailSerializer
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from .models import User
import json

from rest_framework.parsers import JSONParser, FormParser, MultiPartParser

class SignUpView(APIView):
    parser_classes = (JSONParser, FormParser, MultiPartParser)
    
    def post(self, request):
        try:
            data = request.data
            email = data.get('email', '')
            password = data.get('password', '')
            
            # 验证邮箱格式
            if not email:
                return Response(
                    {'error': '邮箱不能为空'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            validate_email(email)
            
            # 验证用户是否存在
            if User.objects.filter(email=email).exists():
                return Response(
                    {'error': '该邮箱已被注册'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            # 使用解析后的数据创建序列化器
            serializer = UserSerializer(data=data)
            if serializer.is_valid():
                user = serializer.save()
                return Response({
                    'message': '注册成功',
                    'data': {
                        'id': user.id,
                        'email': user.email
                    }
                }, status=status.HTTP_201_CREATED)
            return Response({
                'message': '注册失败',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
            
        except ValidationError:
            return Response({
                'message': '注册失败',
                'error': '邮箱格式不正确'
            }, status=status.HTTP_400_BAD_REQUEST)


class SignInView(APIView):
    parser_classes = (JSONParser, FormParser, MultiPartParser)
    
    def post(self, request):
        try:
            data = request.data
            email = data.get('email')
            password = data.get('password')
            
            if not email or not password:
                return Response({
                    'message': '登录失败',
                    'error': '邮箱和密码不能为空'
                }, status=status.HTTP_400_BAD_REQUEST)

            user = authenticate(username=email, password=password)
            
            if user:
                refresh = RefreshToken.for_user(user)
                return Response({
                    'message': '登录成功',
                    'data': {
                        'user': {
                            'id': user.id,
                            'email': user.email
                        },
                        'access_token': str(refresh.access_token),
                        'refresh_token': str(refresh)
                    }
                })
            return Response({
                'message': '登录失败',
                'error': '邮箱或密码错误'
            }, status=status.HTTP_401_UNAUTHORIZED)
            
        except Exception as e:
            return Response({
                'message': '登录失败',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserDetailSerializer(request.user)
        return Response({
            'message': '获取用户信息成功',
            'data': serializer.data
        })
