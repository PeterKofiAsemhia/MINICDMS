from django.db import models
from django.utils import timezone


class Member(models.Model):
    ROLE_CHOICES = [
        ('user', 'User'),
        ('admin', 'Admin'),
    ]

    employee_id = models.CharField(max_length=50, unique=True, blank=True, null=True)
    zk_uid = models.IntegerField(unique=True, null=True, blank=True, help_text="The UID on the ZKTeco device")
    name = models.CharField(max_length=100)
    password = models.CharField(max_length=100, default='123456')
    privilege = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    fingerprint_status = models.CharField(max_length=20, default='pending')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} (UID: {self.zk_uid or 'N/A'})"


class AttendanceSession(models.Model):
    session_name = models.CharField(max_length=100, default='Main Attendance')
    started_at = models.DateTimeField(default=timezone.now)
    ended_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, default='active')
    summary = models.TextField(blank=True, default='')
    total_members = models.IntegerField(default=0)
    present_count = models.IntegerField(default=0)
    late_count = models.IntegerField(default=0)
    absent_count = models.IntegerField(default=0)

    class Meta:
        ordering = ['-started_at']

    def __str__(self):
        return f"{self.session_name} - {self.started_at.date()}"


class AttendanceLog(models.Model):
    member = models.ForeignKey(Member, on_delete=models.CASCADE)
    session = models.ForeignKey(AttendanceSession, on_delete=models.SET_NULL, null=True, blank=True)
    timestamp = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=20, default='Present')
    check_type = models.CharField(max_length=10, default='in')
    source = models.CharField(max_length=20, default='device')

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.member.name} - {self.timestamp}"
