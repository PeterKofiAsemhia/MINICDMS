import datetime
import threading
import time

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Max
from django.shortcuts import redirect, render
from django.utils import timezone
from rest_framework.decorators import api_view
from rest_framework.response import Response

from zk import ZK, const

from .models import AttendanceLog, AttendanceSession, Member

DEVICE_STATE = {
    'conn': None,
    'thread': None,
    'connected': False,
    'ip': None,
    'comm_key': None,
    'monitoring': False,
    'device_name': None,
    'serial_number': None,
    'firmware_version': None,
    'platform': None,
    'user_capacity': None,
    'fingerprint_capacity': None,
}


def _get_session_summary(session):
    members = Member.objects.all()
    session.total_members = members.count()

    if not session.id:
        session.save()

    present_members = set(
        log.member_id for log in AttendanceLog.objects.filter(session=session)
    )
    present_count = len(present_members)
    late_count = 0

    for member_id in present_members:
        first_log = AttendanceLog.objects.filter(session=session, member_id=member_id).order_by('timestamp').first()
        if first_log and first_log.timestamp.time() > datetime.time(9, 0):
            late_count += 1

    absent_count = max(0, members.count() - present_count)
    session.present_count = present_count
    session.late_count = late_count
    session.absent_count = absent_count
    session.summary = (
        f"Present: {present_count}, Late: {late_count}, Absent: {absent_count}, "
        f"Total Members: {members.count()}"
    )
    session.save()
    return session


def _session_active():
    return AttendanceSession.objects.filter(status='active').order_by('-started_at').first()


def _pause_device_monitoring():
    DEVICE_STATE['monitoring'] = False
    thread = DEVICE_STATE['thread']
    if thread and thread.is_alive():
        thread.join(timeout=0.5)


def _resume_device_monitoring():
    if not DEVICE_STATE['ip']:
        return

    if DEVICE_STATE['thread'] is None or not DEVICE_STATE['thread'].is_alive():
        try:
            conn = ZK(DEVICE_STATE['ip'], port=4370, timeout=10, password=int(DEVICE_STATE['comm_key'] or 0))
            DEVICE_STATE['conn'] = conn.connect()
            DEVICE_STATE['connected'] = True
        except Exception:
            DEVICE_STATE['conn'] = None
            DEVICE_STATE['connected'] = False
            return

        DEVICE_STATE['monitoring'] = True
        DEVICE_STATE['thread'] = threading.Thread(target=_scan_device_loop, daemon=True)
        DEVICE_STATE['thread'].start()


def _enroll_member_fingerprint(member):
    if not member.zk_uid:
        return False, 'Member has no device UID set for fingerprint enrollment.'

    if not DEVICE_STATE['ip']:
        return False, 'Device is not connected. Connect the device before enrolling a fingerprint.'

    _pause_device_monitoring()
    device_conn = None

    try:
        zk_conn = ZK(DEVICE_STATE['ip'], port=4370, timeout=60, password=int(DEVICE_STATE['comm_key'] or 123))
        device_conn = zk_conn.connect()
        device_conn.disable_device()
        device_conn.set_user(
            uid=member.zk_uid,
            name=member.name,
            privilege=const.USER_ADMIN if member.privilege == 'admin' else const.USER_DEFAULT,
            password=member.password,
            user_id=str(member.employee_id or member.id),
        )
        device_conn.refresh_data()
        success = device_conn.enroll_user(uid=member.zk_uid, temp_id=0)
        print(f"[ZKTeco] Enrollment result for UID {member.zk_uid}: {success}")

        if success:
            member.fingerprint_status = 'enrolled'
            member.save(update_fields=['fingerprint_status', 'updated_at'])
            print(f"[ZKTeco] DB updated: Member {member.id} ({member.name}) -> enrolled")
            return True, 'Fingerprint enrolled successfully.'

        member.fingerprint_status = 'pending'
        member.save(update_fields=['fingerprint_status', 'updated_at'])
        print(f"[ZKTeco] DB updated: Member {member.id} ({member.name}) -> pending")
        return False, 'Fingerprint enrollment was not completed on the device.'
    except Exception as exc:
        member.fingerprint_status = 'pending'
        member.save(update_fields=['fingerprint_status', 'updated_at'])
        print(f"[ZKTeco] Enrollment exception for UID {member.zk_uid}: {exc}")
        return False, str(exc)
    finally:
        try:
            if device_conn is not None:
                device_conn.enable_device()
                device_conn.disconnect()
        except Exception:
            pass

        DEVICE_STATE['conn'] = None
        DEVICE_STATE['connected'] = False
        _resume_device_monitoring()


def _refresh_device_metadata(conn=None):
    if conn is None:
        conn = DEVICE_STATE.get('conn')
    if conn is None:
        return

    try:
        conn.read_sizes()
        DEVICE_STATE['user_capacity'] = getattr(conn, 'users_cap', DEVICE_STATE.get('user_capacity'))
        DEVICE_STATE['fingerprint_capacity'] = getattr(conn, 'fingers_cap', DEVICE_STATE.get('fingerprint_capacity'))
        DEVICE_STATE['device_name'] = conn.get_device_name() or DEVICE_STATE.get('device_name')
        DEVICE_STATE['serial_number'] = conn.get_serialnumber() or DEVICE_STATE.get('serial_number')
        DEVICE_STATE['firmware_version'] = conn.get_firmware_version() or DEVICE_STATE.get('firmware_version')
        DEVICE_STATE['platform'] = conn.get_platform() or DEVICE_STATE.get('platform')
    except Exception:
        pass


def _sync_device_users_to_members(conn=None):
    if conn is None:
        conn = DEVICE_STATE.get('conn')
    if conn is None:
        return

    _refresh_device_metadata(conn)

    try:
        device_users = conn.get_users()
    except Exception:
        return

    device_uids = set()
    for user in device_users:
        uid = getattr(user, 'uid', None)
        if uid is None:
            continue
        uid_int = int(uid)
        device_uids.add(uid_int)

        member = Member.objects.filter(zk_uid=uid_int).first()
        if member is None:
            member, _ = Member.objects.get_or_create(
                employee_id=str(getattr(user, 'user_id', uid_int)),
                defaults={
                    'name': getattr(user, 'name', f'Guest-{uid_int}'),
                    'zk_uid': uid_int,
                    'fingerprint_status': 'enrolled',
                    'privilege': 'admin' if getattr(user, 'privilege', 0) in (const.USER_ADMIN, const.USER_MANAGER, const.USER_ENROLLER) else 'user',
                },
            )

        member.zk_uid = uid_int
        member.employee_id = str(getattr(user, 'user_id', member.employee_id or uid_int))
        member.name = getattr(user, 'name', member.name) or member.name or f'Guest-{uid_int}'
        member.privilege = 'admin' if getattr(user, 'privilege', 0) in (const.USER_ADMIN, const.USER_MANAGER, const.USER_ENROLLER) else 'user'
        member.fingerprint_status = 'enrolled'
        member.save(update_fields=['zk_uid', 'employee_id', 'name', 'privilege', 'fingerprint_status', 'updated_at'])

    for member in Member.objects.filter(zk_uid__isnull=False):
        if member.zk_uid not in device_uids:
            member.fingerprint_status = 'pending'
            member.save(update_fields=['fingerprint_status', 'updated_at'])


def _scan_device_loop():
    while DEVICE_STATE.get('monitoring', False) and DEVICE_STATE['connected'] and DEVICE_STATE['conn'] is not None:
        try:
            _sync_device_users_to_members(DEVICE_STATE['conn'])
            records = DEVICE_STATE['conn'].get_attendance()
            session = _session_active()
            if not records:
                time.sleep(2)
                continue
            for record in records:
                user_id = getattr(record, 'user_id', None)
                uid = getattr(record, 'uid', None)
                timestamp = getattr(record, 'timestamp', timezone.now())
                name = getattr(record, 'name', None)

                if uid is None and user_id is None:
                    continue

                try:
                    member = Member.objects.get(zk_uid=int(uid) if uid is not None else int(user_id))
                except (ValueError, TypeError, Member.DoesNotExist):
                    member = None
                    if user_id is not None:
                        member, _ = Member.objects.get_or_create(
                            employee_id=str(user_id),
                            defaults={'name': name or f'Guest-{user_id}', 'zk_uid': int(uid) if uid is not None else int(user_id), 'fingerprint_status': 'enrolled'}
                        )
                    elif uid is not None:
                        member, _ = Member.objects.get_or_create(
                            zk_uid=int(uid),
                            defaults={'employee_id': str(uid), 'name': name or f'Guest-{uid}', 'fingerprint_status': 'enrolled'}
                        )

                if member is None:
                    continue

                if isinstance(timestamp, str):
                    try:
                        timestamp = datetime.datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                        if timezone.is_naive(timestamp):
                            timestamp = timezone.make_aware(timestamp)
                    except ValueError:
                        timestamp = timezone.now()
                elif timezone.is_naive(timestamp):
                    timestamp = timezone.make_aware(timestamp)

                if session:
                    already_logged = AttendanceLog.objects.filter(member=member, session=session, timestamp__date=timestamp.date(), check_type='in').exists()
                    if not already_logged:
                        AttendanceLog.objects.create(
                            member=member,
                            session=session,
                            timestamp=timestamp,
                            status='Present',
                            check_type='in',
                            source='device',
                        )
                        session = _session_active()
                        if session:
                            _get_session_summary(session)

            time.sleep(2)
        except Exception:
            time.sleep(3)


@login_required(login_url='/login/')
def dashboard(request):
    members = Member.objects.all().order_by('name')
    active_session = _session_active()
    logs = AttendanceLog.objects.select_related('member').order_by('-timestamp')[:25]
    today = timezone.now().date()
    enrollment_pending = request.session.pop('enrollment_pending', False)
    enrollment_complete = request.session.pop('enrollment_complete', False)

    if active_session:
        _resume_device_monitoring()
        _sync_device_users_to_members()
        _get_session_summary(active_session)

    _sync_device_users_to_members()

    today_present = AttendanceLog.objects.filter(timestamp__date=today).count()
    late_count = AttendanceLog.objects.filter(timestamp__date=today).filter(timestamp__time__gt=datetime.time(9, 0)).count()
    pending_fingerprints = Member.objects.filter(fingerprint_status='pending').count()

    context = {
        'members': members,
        'logs': logs,
        'device_connected': DEVICE_STATE['connected'],
        'device_ip': DEVICE_STATE['ip'],
        'device_name': DEVICE_STATE.get('device_name'),
        'serial_number': DEVICE_STATE.get('serial_number'),
        'firmware_version': DEVICE_STATE.get('firmware_version'),
        'platform': DEVICE_STATE.get('platform'),
        'user_capacity': DEVICE_STATE.get('user_capacity'),
        'fingerprint_capacity': DEVICE_STATE.get('fingerprint_capacity'),
        'active_session': active_session,
        'member_count': members.count(),
        'today_present': today_present,
        'late_count': late_count,
        'pending_fingerprints': pending_fingerprints,
        'today_date': timezone.now().strftime('%A, %d %B %Y'),
        'device_status': 'Connected' if DEVICE_STATE['connected'] else 'Disconnected',
        'enrollment_pending': enrollment_pending,
        'enrollment_complete': enrollment_complete,
    }
    return render(request, 'dashboard.html', context)


@login_required(login_url='/login/')
def connect_device(request):
    if request.method != 'POST':
        return redirect('dashboard')

    ip = request.POST.get('ip', '').strip()
    comm_key = request.POST.get('comm_key', '').strip()

    try:
        conn = ZK(ip, port=4370, timeout=10, password=int(comm_key))
        device = conn.connect()
        DEVICE_STATE['conn'] = device
        DEVICE_STATE['connected'] = True
        DEVICE_STATE['ip'] = ip
        DEVICE_STATE['comm_key'] = comm_key

        DEVICE_STATE['monitoring'] = True
        _refresh_device_metadata(device)
        _sync_device_users_to_members(device)
        if DEVICE_STATE['thread'] is None or not DEVICE_STATE['thread'].is_alive():
            DEVICE_STATE['thread'] = threading.Thread(target=_scan_device_loop, daemon=True)
            DEVICE_STATE['thread'].start()

        request.session['device_connected'] = True
        request.session['device_ip'] = ip
        return redirect('dashboard')
    except Exception as exc:
        DEVICE_STATE['connected'] = False
        DEVICE_STATE['conn'] = None
        return render(request, 'dashboard.html', {'device_error': str(exc), 'device_connected': False})


@login_required(login_url='/login/')
def register_member(request):
    if request.method != 'POST':
        return redirect('dashboard')

    member_id = request.POST.get('member_id', '').strip()
    employee_id = request.POST.get('employee_id', '').strip()
    name = request.POST.get('name', '').strip()
    uid = request.POST.get('zk_uid', '').strip()
    password = request.POST.get('password', '').strip() or '123456'
    privilege = request.POST.get('privilege', 'user')
    enroll_fingerprint_now = request.POST.get('enroll_fingerprint') == 'on'

    if not employee_id or not name:
        return redirect('dashboard')

    if member_id:
        try:
            member = Member.objects.get(id=member_id)
        except Member.DoesNotExist:
            return redirect('dashboard')
        member.employee_id = employee_id
        member.name = name
        member.password = password
        member.privilege = privilege
        if uid:
            member.zk_uid = int(uid)
        elif member.zk_uid is None:
            next_uid = (Member.objects.filter(zk_uid__isnull=False).aggregate(max_uid=Max('zk_uid'))['max_uid'] or 0) + 1
            member.zk_uid = next_uid
        member.fingerprint_status = 'pending' if member.zk_uid is not None and member.fingerprint_status != 'enrolled' else member.fingerprint_status
        member.save()
    else:
        if uid:
            zk_uid = int(uid)
        else:
            zk_uid = (Member.objects.filter(zk_uid__isnull=False).aggregate(max_uid=Max('zk_uid'))['max_uid'] or 0) + 1

        member, created = Member.objects.get_or_create(
            employee_id=employee_id,
            defaults={
                'name': name,
                'password': password,
                'privilege': privilege,
                'zk_uid': zk_uid,
                'fingerprint_status': 'pending',
            },
        )

        if not created:
            member.name = name
            member.password = password
            member.privilege = privilege
            member.zk_uid = zk_uid if member.zk_uid is None else member.zk_uid
            member.fingerprint_status = 'pending' if member.zk_uid is not None else member.fingerprint_status
            member.save()

    if DEVICE_STATE['connected'] and member.zk_uid:
        try:
            DEVICE_STATE['conn'].set_user(
                uid=member.zk_uid,
                name=member.name,
                privilege=const.USER_ADMIN if privilege == 'admin' else const.USER_DEFAULT,
                password=password,
                user_id=str(employee_id),
            )
            member.fingerprint_status = 'pending'
            member.save(update_fields=['fingerprint_status', 'updated_at'])
        except Exception:
            pass

    if enroll_fingerprint_now:
        messages.info(
            request,
            f'Place {member.name}\'s finger on the device and scan it 3 times to complete registration.',
        )
        success, detail = _enroll_member_fingerprint(member)
        if success:
            messages.success(request, detail)
        else:
            messages.error(request, detail)

    return redirect('dashboard')


@login_required(login_url='/login/')
def delete_member(request):
    if request.method != 'POST':
        return redirect('dashboard')

    member_id = request.POST.get('member_id')
    if not member_id:
        return redirect('dashboard')

    try:
        member = Member.objects.get(id=member_id)
    except Member.DoesNotExist:
        return redirect('dashboard')

    if DEVICE_STATE['connected'] and member.zk_uid is not None:
        try:
            DEVICE_STATE['conn'].delete_user(uid=member.zk_uid)
        except Exception:
            pass

    member.delete()
    messages.success(request, f'{member.name} was deleted successfully.')
    return redirect('dashboard')


@login_required(login_url='/login/')
def enroll_member_fingerprint(request):
    if request.method != 'POST':
        return redirect('dashboard')

    member_id = request.POST.get('member_id')
    if not member_id:
        return redirect('dashboard')

    try:
        member = Member.objects.get(id=member_id)
    except Member.DoesNotExist:
        return redirect('dashboard')

    request.session['enrollment_pending'] = True
    request.session['enrollment_complete'] = False
    request.session.modified = True
    messages.info(
        request,
        f'Place {member.name}\'s finger on the device and scan it 3 times to enroll the fingerprint.',
    )

    success, detail = _enroll_member_fingerprint(member)
    request.session['last_enrollment_result'] = detail
    request.session['last_enrollment_success'] = success
    request.session['enrollment_pending'] = False
    request.session['enrollment_complete'] = success
    request.session.modified = True

    if success:
        messages.success(request, detail)
    else:
        messages.error(request, detail)

    return redirect('dashboard')


@login_required(login_url='/login/')
def start_session(request):
    if request.method != 'POST':
        return redirect('dashboard')

    session = AttendanceSession.objects.filter(status='active').first()
    if session is None:
        session = AttendanceSession.objects.create(status='active', session_name='Church Attendance')

    if DEVICE_STATE.get('connected') and DEVICE_STATE.get('ip'):
        _resume_device_monitoring()

    return redirect('dashboard')


@login_required(login_url='/login/')
def end_session(request):
    if request.method != 'POST':
        return redirect('dashboard')

    session = AttendanceSession.objects.filter(status='active').order_by('-started_at').first()
    if session:
        session.status = 'ended'
        session.ended_at = timezone.now()
        _get_session_summary(session)
        session.save()
    return redirect('dashboard')


@api_view(['POST'])
def sync_attendance(request):
    """Expects JSON from the local script: {'zk_uid': '1', 'timestamp': '2023-10-27 08:30:00'}"""
    zk_uid = request.data.get('zk_uid')
    timestamp_str = request.data.get('timestamp')

    try:
        member = Member.objects.get(zk_uid=int(zk_uid))
        timestamp = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        timestamp = timezone.make_aware(timestamp)

        session = _session_active()
        if not AttendanceLog.objects.filter(member=member, timestamp=timestamp, source='device').exists():
            AttendanceLog.objects.create(member=member, timestamp=timestamp, session=session, status='Present', check_type='in', source='device')
            if session:
                _get_session_summary(session)
            return Response({'status': 'success', 'message': 'Log saved'})

        return Response({'status': 'ignored', 'message': 'Log already exists'})
    except Member.DoesNotExist:
        return Response({'status': 'error', 'message': 'Member not found in Django'}, status=404)
    except Exception as exc:
        return Response({'status': 'error', 'message': str(exc)}, status=400)
