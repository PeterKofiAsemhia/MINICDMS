from unittest.mock import Mock, call, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from zk.user import User

from .models import AttendanceSession, Member
from .views import DEVICE_STATE, _enroll_member_fingerprint, _sync_device_users_to_members


class AttendanceAuthFlowTests(TestCase):
    def test_dashboard_requires_login(self):
        response = self.client.get(reverse('dashboard'))

        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)

    def test_authenticated_user_can_view_dashboard(self):
        user = get_user_model().objects.create_user(
            username='admin',
            password='strong-password-123',
        )
        self.client.force_login(user)

        response = self.client.get(reverse('dashboard'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Attendance Dashboard')
        self.assertContains(response, 'Logout')

    def test_member_fingerprint_enrollment_route_updates_pending_member(self):
        user = get_user_model().objects.create_user(
            username='admin2',
            password='strong-password-123',
        )
        self.client.force_login(user)
        member = Member.objects.create(
            employee_id='E-101',
            name='Jane Doe',
            zk_uid=12,
            fingerprint_status='pending',
        )

        response = self.client.post(reverse('enroll_member_fingerprint'), {'member_id': member.id})

        self.assertEqual(response.status_code, 302)
        member.refresh_from_db()
        self.assertEqual(member.fingerprint_status, 'pending')

    @patch('core.views._enroll_member_fingerprint', return_value=(True, 'Fingerprint enrolled successfully.'))
    def test_member_fingerprint_route_updates_dashboard_immediately_after_success(self, mock_enroll):
        user = get_user_model().objects.create_user(
            username='admin2b',
            password='strong-password-123',
        )
        self.client.force_login(user)
        member = Member.objects.create(
            employee_id='E-101-B',
            name='Jane Doe B',
            zk_uid=123,
            fingerprint_status='pending',
        )

        response = self.client.post(reverse('enroll_member_fingerprint'), {'member_id': member.id}, follow=False)

        self.assertEqual(response.status_code, 302)
        self.assertTrue(self.client.session.get('enrollment_complete'))
        mock_enroll.assert_called_once_with(member)

    def test_dashboard_refreshes_after_enrollment_success(self):
        user = get_user_model().objects.create_user(
            username='admin-refresh',
            password='strong-password-123',
        )
        self.client.force_login(user)
        session = self.client.session
        session['enrollment_complete'] = True
        session.save()

        response = self.client.get(reverse('dashboard'))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['enrollment_complete'])
        self.assertContains(response, 'window.location.reload();')

    def test_sync_device_users_updates_member_fingerprint_status(self):
        member = Member.objects.create(employee_id='E-500', name='Machine User', zk_uid=11, fingerprint_status='pending')
        stale_member = Member.objects.create(employee_id='E-501', name='Old User', zk_uid=12, fingerprint_status='enrolled')
        fake_conn = Mock()
        fake_conn.get_users.return_value = [
            User(uid=11, name='Machine User', privilege=0, password='123456', user_id='500'),
            User(uid=13, name='New Device User', privilege=0, password='123456', user_id='501'),
        ]

        _sync_device_users_to_members(fake_conn)

        member.refresh_from_db()
        stale_member.refresh_from_db()
        self.assertEqual(member.fingerprint_status, 'enrolled')
        self.assertEqual(stale_member.fingerprint_status, 'pending')
        self.assertTrue(Member.objects.filter(zk_uid=13, fingerprint_status='enrolled').exists())

    def test_register_member_without_uid_assigns_next_available_uid(self):
        user = get_user_model().objects.create_user(
            username='admin3',
            password='strong-password-123',
        )
        self.client.force_login(user)
        Member.objects.create(employee_id='E-100', name='Existing User', zk_uid=5)

        response = self.client.post(
            reverse('register_member'),
            {
                'employee_id': 'E-200',
                'name': 'New Member',
                'password': '123456',
                'privilege': 'user',
            },
        )

        self.assertEqual(response.status_code, 302)
        member = Member.objects.get(employee_id='E-200')
        self.assertEqual(member.zk_uid, 6)

    def test_delete_member_route_removes_member(self):
        user = get_user_model().objects.create_user(
            username='admin4',
            password='strong-password-123',
        )
        self.client.force_login(user)
        member = Member.objects.create(employee_id='E-300', name='Old Member', zk_uid=99)

        response = self.client.post(reverse('delete_member'), {'member_id': member.id})

        self.assertEqual(response.status_code, 302)
        self.assertFalse(Member.objects.filter(id=member.id).exists())

    @patch('core.views._resume_device_monitoring')
    def test_start_session_resumes_scanner_when_device_is_connected(self, mock_resume):
        user = get_user_model().objects.create_user(
            username='admin5',
            password='strong-password-123',
        )
        self.client.force_login(user)
        DEVICE_STATE['connected'] = True
        DEVICE_STATE['ip'] = '192.168.1.201'
        DEVICE_STATE['comm_key'] = '123'
        AttendanceSession.objects.filter(status='active').delete()

        response = self.client.post(reverse('start_session'))

        self.assertEqual(response.status_code, 302)
        self.assertTrue(AttendanceSession.objects.filter(status='active').exists())
        mock_resume.assert_called_once()

    @patch('core.views.ZK')
    def test_enroll_member_fingerprint_uses_fresh_device_connection(self, mock_zk):
        member = Member.objects.create(employee_id='E-400', name='Alice', zk_uid=50, fingerprint_status='pending')
        fake_conn = Mock()
        fake_conn.connect.return_value = fake_conn
        fake_conn.set_user.return_value = True
        fake_conn.enroll_user.return_value = True
        mock_zk.return_value = fake_conn

        DEVICE_STATE['connected'] = True
        DEVICE_STATE['conn'] = Mock()
        DEVICE_STATE['ip'] = '192.168.1.201'
        DEVICE_STATE['comm_key'] = '123'

        success, detail = _enroll_member_fingerprint(member)

        self.assertTrue(success)
        self.assertIn('successfully', detail.lower())
        self.assertIn(call('192.168.1.201', port=4370, timeout=60, password=123), mock_zk.call_args_list)
        fake_conn.disable_device.assert_called_once()
        fake_conn.enable_device.assert_called_once()
        fake_conn.disconnect.assert_called_once()
