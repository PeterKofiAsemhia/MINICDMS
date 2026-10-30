from django.contrib.auth import views as auth_views
from django.urls import path

from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='/login/'), name='logout'),
    path('connect-device/', views.connect_device, name='connect_device'),
    path('register-member/', views.register_member, name='register_member'),
    path('delete-member/', views.delete_member, name='delete_member'),
    path('enroll-member-fingerprint/', views.enroll_member_fingerprint, name='enroll_member_fingerprint'),
    path('start-session/', views.start_session, name='start_session'),
    path('end-session/', views.end_session, name='end_session'),
    path('api/sync/', views.sync_attendance, name='sync_attendance'),
]