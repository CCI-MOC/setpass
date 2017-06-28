import datetime
import json
import uuid

import pytest
import freezegun

from setpass import api
from setpass import config
from setpass import model
from setpass import wsgi
from setpass import exception

CONF = config.CONF

model.db.create_all()


class TestSetpass(object):
    @staticmethod
    def create(changed=False):
        user = model.User(
            user_id=str(uuid.uuid4()),
            token=str(uuid.uuid4()),
            pin='1234',
            password=str(uuid.uuid4())
        )
        model.db.session.add(user)
        model.db.session.commit()
        return user

    @staticmethod
    def delete(user):
        assert isinstance(user, model.User)
        model.db.session.delete(user)
        model.db.session.commit()

    @pytest.fixture
    def user(self):
        user = self.create()
        yield user
        self.delete(user)

    @pytest.fixture()
    def app(self):
        return wsgi.app.test_client()

    @staticmethod
    def _get_expired_time(timestamp):
        return timestamp + \
               datetime.timedelta(seconds=CONF['token_expiration'] + 5)

    @staticmethod
    def _get_auth_headers():
        return {'x-auth-token': str(uuid.uuid4())}

    # Internal method tests
    def test_internal_wrong_token(self, user):
        wrong_token = 'wrong_token'
        assert wrong_token != user.token

        with pytest.raises(exception.TokenNotFoundException):
            api._set_password(wrong_token, user.pin, 'password2')

    def test_internal_set_password_twice(self, user, mocker):
        mocker.patch('setpass.api._set_openstack_password', return_value=True)

        pin = user.pin
        api._set_password(user.token, pin, 'new_password')
        with pytest.raises(exception.TokenNotFoundException):
            api._set_password(user.token, pin, 'another_new_password')

    def test_internal_expired_token(self, user):
        with freezegun.freeze_time(self._get_expired_time(user.updated_at)):
            with pytest.raises(exception.TokenExpiredException):
                api._set_password(user.token, user.pin, 'new_password')

    # API Tests
    def test_add_new_user(self, app, mocker):
        mocker.patch('setpass.api._check_admin_token', return_value=True)

        user_id = str(uuid.uuid4())
        pin = '1234'
        password = str(uuid.uuid4())
        payload = json.dumps({'password': password, 'pin': pin})

        with freezegun.freeze_time("2016-01-01"):
            timestamp = datetime.datetime.utcnow()
            r = app.put('/token/%s' % user_id,
                        data=payload,
                        headers=self._get_auth_headers())

        user = model.User.find(token=r.data)
        assert user.user_id == user_id
        assert user.password == password
        assert user.pin == pin
        assert timestamp == user.updated_at
        assert r.status_code == 200

    def test_add_no_token(self, app):
        user_id = str(uuid.uuid4())
        pin = '1234'
        password = str(uuid.uuid4())
        payload = json.dumps({'password': password, 'pin': pin})

        r = app.put('/token/%s' % user_id, data=payload)

        assert r.status_code == 401

    def test_add_wrong_token(self, app, mocker):
        mocker.patch('setpass.api._check_admin_token', return_value=False)

        user_id = str(uuid.uuid4())
        pin = '1234'
        password = str(uuid.uuid4())
        payload = json.dumps({'password': password, 'pin': pin})

        r = app.put('/token/%s' % user_id,
                    data=payload,
                    headers=self._get_auth_headers())

        assert r.status_code == 403

    def test_add_update_pin(self, app, user, mocker):
        mocker.patch('setpass.api._check_admin_token', return_value=True)

        old_token = user.token
        new_pin = '9876'
        payload = {'pin': new_pin}

        with freezegun.freeze_time("2016-01-01"):
            timestamp = datetime.datetime.utcnow()
            r = app.put('/token/%s' % user.user_id,
                        data=json.dumps(payload),
                        headers=self._get_auth_headers())

        assert user.pin == new_pin
        assert user.token != old_token
        assert timestamp == user.updated_at
        assert r.data == user.token
        assert r.status_code == 200

    def test_add_update_password(self, app, user, mocker):
        mocker.patch('setpass.api._check_admin_token', return_value=True)

        old_token = user.token
        new_password = str(uuid.uuid4())
        payload = {'password': new_password}

        with freezegun.freeze_time("2016-01-01"):
            timestamp = datetime.datetime.utcnow()
            r = app.put('/token/%s' % user.user_id,
                        data=json.dumps(payload),
                        headers=self._get_auth_headers())

        assert user.password == new_password
        assert user.token != old_token
        assert timestamp == user.updated_at
        assert r.data == user.token
        assert r.status_code == 200

    def test_add_update_pin_and_password(self, app, user, mocker):
        mocker.patch('setpass.api._check_admin_token', return_value=True)

        pin = '1234'
        password = str(uuid.uuid4())
        payload = json.dumps({'password': password, 'pin': pin})

        with freezegun.freeze_time("2016-01-01"):
            timestamp = datetime.datetime.utcnow()
            r = app.put('/token/%s' % user.user_id,
                        data=payload,
                        headers=self._get_auth_headers())

        assert user.password == password
        assert user.pin == pin
        assert timestamp == user.updated_at
        assert r.status_code == 200

    def test_set_pass(self, app, user, mocker):
        mocker.patch('setpass.api._set_openstack_password', return_value=True)

        # Change password
        token = user.token
        pin = user.pin  # Save the pin to reuse it after row deletion
        r = app.post('/?token=%s' % token,
                     data={'password': 'NEW_PASS',
                           'confirm_password': 'NEW_PASS',
                           'pin': pin})
        assert r.status_code == 200

        # Ensure user record is deleted
        user = model.User.find(token=token)
        assert user is None

        # Ensure we get a 404 when reusing the token
        r = app.post('/?token=%s' % token,
                     data={'password': 'NEW_NEW_PASS',
                           'confirm_password': 'NEW_NEW_PASS',
                           'pin': pin})
        assert r.status_code == 404

    def test_set_pass_expired(self, app, user):
        # Set time to after token expiration
        with freezegun.freeze_time(self._get_expired_time(user.updated_at)):
            r = app.post('/?token=%s' % user.token,
                         data={'password': 'NEW_PASS',
                               'confirm_password': 'NEW_PASS',
                               'pin': user.pin})

        assert r.status_code == 403

    def test_wrong_token(self, app, user):
        r = app.post('/?token=%s' % 'WRONG_TOKEN',
                     data={'password': 'NEW_PASS',
                           'confirm_password': 'NEW_PASS',
                           'pin': user.pin})
        assert r.status_code == 404

    def test_wrong_pin(self, app, user):
        pin = '0000'
        assert pin != user.pin

        r = app.post('/?token=%s' % user.token,
                     data={'password': 'NEW_PASS',
                           'confirm_password': 'NEW_PASS',
                           'pin': pin})
        assert r.status_code == 403

    def test_lockout(self, app, user):
        token = user.token
        pin = '0000'
        assert pin != user.pin
        assert user.attempts == 0

        # Set the current number of attempts to the max
        user.attempts = CONF.max_attempts
        model.db.session.commit()

        app.post('/?token=%s' % user.token,
                 data={'password': 'NEW_PASS',
                       'confirm_password': 'NEW_PASS',
                       'pin': pin})

        user = model.User.find(token=token)
        assert user is not None
        assert user.attempts == CONF.max_attempts + 1

        # Provide the correct pin, but we went beyond max attempts
        r = app.post('/?token=%s' % user.token,
                     data={'password': 'NEW_PASS',
                           'confirm_password': 'NEW_PASS',
                           'pin': user.pin})
        assert r.status_code == 403

    def test_invalid_pin(self, app, user):
        pin = 'fooo'

        r = app.post('/?token=%s' % user.token,
                     data={'password': 'NEW_PASS',
                           'confirm_password': 'NEW_PASS',
                           'pin': pin})
        assert r.status_code == 403

    def test_no_match(self, app, user):
        r = app.post('/?token=%s' % user.token,
                     data={'password': 'NEW_PASS',
                           'confirm_password': 'NOT_A_MATCH',
                           'pin': user.pin})
        assert r.status_code == 400

    def test_no_arguments(self, app):
        # Token but no password
        r = app.post('/?token=%s' % 'TOKEN')
        assert r.status_code == 400

        # Password but no token
        r = app.post('/', data={'password': 'NEW_PASS'})
        assert r.status_code == 400
