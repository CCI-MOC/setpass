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

from os import path

from oslo_config import cfg

CONF = cfg.CONF

default_opts = [
    cfg.StrOpt('database',
               default='sqlite:///',
               help='Database uri'),

    cfg.IntOpt('port',
               default=5001,
               help='Web server port number.'),

    cfg.StrOpt('auth_url',
               default='http://localhost:5000/v3',
               help='Identity service authentication url.'),

    cfg.StrOpt('admin_project_name',
               default='admin',
               help='Admin project name'),

    cfg.StrOpt('admin_project_domain_id',
               default='default',
               help='Admin project domain id'),

    cfg.IntOpt('token_expiration',
               default=False,
               help='Time in seconds that a token is valid.'),

    cfg.IntOpt('max_attempts',
               default=3,
               help='Max number of pin attempts before lockout.'),

    cfg.StrOpt('helpdesk_email',
               default='root@localhost',
               help='Destination email for password reset notification.'),

    cfg.StrOpt('ticket_sender',
               default='root@localhost',
               help='Source email for password reset notification.'),

    cfg.StrOpt('ticket_subject',
               default='New Ticket',
               help='Email address for password reset notification.'),

    cfg.HostAddressOpt('mail_ip',
                       default='127.0.0.1',
                       help='IP address of the mail server.'),

    cfg.PortOpt('mail_port',
                default=25,
                help='Port of the mail server.'),

    cfg.StrOpt('helpdesk_template',
               default='setpass/files/helpdesk_ticket.txt',
               help='Template file for helpdesk ticket emails')
]

CONF.register_opts(default_opts)


def load_config():
    """Load parameters from the proxy's config file."""
    conf_files = [f for f in ['setpass.conf',
                              'etc/setpass.conf',
                              '/etc/setpass.conf'] if path.isfile(f)]
    if conf_files is not []:
        CONF(default_config_files=conf_files)


load_config()
