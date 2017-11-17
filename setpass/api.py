#   Copyright 2016 Massachusetts Open Cloud
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

import datetime
import json
import smtplib
import uuid

from email.mime.text import MIMEText
from flask import Response
from flask import request, render_template
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneauth1.exceptions import http as ksa_exceptions

from setpass import config
from setpass import model
from setpass import wsgi
from setpass import exception

application = wsgi.app

CONF = config.CONF


@wsgi.app.route('/', methods=['GET'])
def view_form():
    token = request.args.get('token', None)
    if not token:
        return Response(response='Token not found', status=404)

    return render_template('password_form.html')


@wsgi.app.route('/', methods=['POST'])
def set_password():
    token = request.args.get('token')
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    pin = request.form['pin']

    if not token or not password or not confirm_password or not pin:
        return Response(response='Missing required field!', status=400)

    if password != confirm_password:
        return Response(response='Passwords do not match', status=400)

    try:
        _set_password(token, pin, password)
    except exception.TokenNotFoundException:
        return Response(response='Token not found', status=404)
    except exception.TokenExpiredException:
        return Response(response='Token expired', status=403)
    except exception.WrongPinException:
        return Response(response='Wrong pin', status=403)
    except exception.OpenStackError as e:
        return Response(response=e.message, status=500)
    except exception.AccountLocked:
        return Response(response='Account locked, too many wrong attempts!',
                        status=403)

    return Response(response='Password set.', status=200)


def _set_openstack_password(user_id, old_password, new_password):
    auth = v3.Password(auth_url=CONF.auth_url,
                       user_id=user_id,
                       password=old_password)

    sess = session.Session(auth=auth)

    url = '%s/users/%s/password' % (CONF.auth_url, user_id)
    payload = {'user': {'password': new_password,
                        'original_password': old_password}}

    header = {'Content-Type': 'application/json'}
    r = sess.post(url, headers=header, data=json.dumps(payload))

    if 200 <= r.status_code < 300:
        return True
    else:
        raise exception.OpenStackError(r.text)


def _check_admin_token(token):
    auth = v3.Token(auth_url=CONF.auth_url,
                    token=token,
                    project_name=CONF.admin_project_name,
                    project_domain_id=CONF.admin_project_domain_id)

    sess = session.Session(auth=auth)
    # If we're able to scope succesfully to the admin project with this
    # token, assume admin.
    try:
        sess.get_token()
        return True
    except ksa_exceptions.Unauthorized:
        return False


def _increase_attempts(user):
    user.attempts += 1
    model.db.session.commit()


def _set_password(token, pin, password):
    # Find user for token
    user = model.User.find(token=token)

    if user is None:
        raise exception.TokenNotFoundException

    if user.attempts > CONF.max_attempts:
        raise exception.AccountLocked

    if pin != user.pin:
        _increase_attempts(user)
        raise exception.WrongPinException

    delta = datetime.datetime.utcnow() - user.updated_at
    if delta.total_seconds() > CONF.token_expiration:
        raise exception.TokenExpiredException

    _set_openstack_password(user.user_id, user.password, password)

    model.db.session.delete(user)
    model.db.session.commit()


@wsgi.app.route('/token/<user_id>', methods=['PUT'])
def add(user_id):
    token = request.headers.get('x-auth-token', None)

    if not token:
        return Response(response='Unauthorized', status=401)

    if not _check_admin_token(token):
        return Response(response='Forbidden', status=403)

    payload = json.loads(request.data)

    user = model.User.find(user_id=user_id)
    if user:
        if 'pin' in payload:
            user.pin = payload['pin']
        if 'password' in payload:
            user.password = payload['password']

        user.token = str(uuid.uuid4())
        user.update_timestamp_and_attempts()
    else:
        user = model.User(
            user_id=user_id,
            token=str(uuid.uuid4()),
            pin=payload['pin'],
            password=payload['password']
        )
        model.db.session.add(user)

    model.db.session.commit()
    return Response(response=user.token, status=200)


@wsgi.app.route('/reset', methods=['GET'])
def view_reset_form():
    return render_template('reset_form.html')


@wsgi.app.route('/reset', methods=['POST'])
def reset_password():
    name = request.form['name']
    email = request.form['email']
    confirm_email = request.form['confirm_email']
    pin = request.form['pin']

    if not name or not email or not confirm_email or not pin:
        return Response(response='Missing required field!', status=400)

    if email != confirm_email:
        return Response(response="Email addresses do not match.", status=400)

    if len(pin) != 4 or not pin.isdigit():
    	return Response(response='Pin should be 4-digit number', status=400)

    _notify_helpdesk(name=name, username=email, pin=pin)

    return Response(response='The request has been forwarded to the helpdesk.',
                    status=200)


def _notify_helpdesk(**kwargs):
    with open(CONF.helpdesk_template, 'r') as f:
        msg_body = f.read()
    msg_body = msg_body.format(**kwargs)

    sender = CONF.ticket_sender
    recipient = CONF.helpdesk_email
    msg = MIMEText(msg_body)
    msg['Subject'] = CONF.ticket_subject
    msg['From'] = sender
    msg['To'] = recipient

    server = smtplib.SMTP(CONF.mail_ip, CONF.mail_port)
    server.ehlo()
    server.starttls()

    server.sendmail(sender, recipient, msg.as_string())


if __name__ == '__main__':
    wsgi.app.run(port=CONF.port, host='0.0.0.0')
