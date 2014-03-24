import random
import string
from twisted.python import log
from email.mime.text import MIMEText
from twisted.internet import defer
from twisted.mail.smtp import sendmail
from zope.interface import implements, classProvides
from automatron.controller.command import IAutomatronCommandHandler
from automatron.controller.controller import IAutomatronClientActions
from automatron.controller.plugin import IAutomatronPluginFactory
from passlib.apps import custom_app_context as pwd_context
import json
from automatron.core.event import STOP
from automatron.core.util import parse_user


class AutomatronRegistration(object):
    classProvides(IAutomatronPluginFactory)
    implements(IAutomatronCommandHandler)

    name = 'registration'
    priority = 100

    command_map = {
        #command: (help, min_args, max_args)
        'identify': ('[channel]', 0, 1),
        'register': ('<password> <email>', 2, 2),
        'verify': ('<verification code>', 1, 1),
    }

    def __init__(self, controller):
        self.controller = controller

    def _msg(self, server, user, message):
        self.controller.plugins.emit(
            IAutomatronClientActions['message'],
            server,
            user,
            message
        )

    def on_command(self, client, user, command, args):
        config = self.command_map.get(command)
        if config is None:
            return

        if not config[1] <= len(args) <= config[2]:
            self._msg(client.server, user, 'Invalid syntax. Use: %s %s' % (command, config[0]))
        else:
            getattr(self, '_on_command_%s' % command)(client, user, *args)
        return STOP

    @defer.inlineCallbacks
    def _on_command_identify(self, client, user, channel=None):
        username, username_relevance = yield self.controller.config.get_username_by_hostmask(client.server, user)
        if username is not None:
            if username_relevance == 0:
                identity = 'You are globally known as %s' % username
            else:
                identity = 'You are known as %s' % username

            role, role_relevance = yield self.controller.config.get_role_by_username(client.server, channel, username)
            if role_relevance is not None and role_relevance < username_relevance:
                role = role_relevance = None

            if role_relevance is None:
                self._msg(client.server, user, identity)
            elif role_relevance in (2, 3):
                self._msg(client.server, user, '%s and your role in %s is %s' % (identity, channel, role))
            else:
                self._msg(client.server, user, '%s and your role is %s' % (identity, role))
        else:
            self._msg(client.server, user, 'I don\'t know you...')

    @defer.inlineCallbacks
    def _on_command_register(self, client, user, password, email):
        nickname = parse_user(user)[0]
        pw_hash = pwd_context.encrypt(password)

        config = yield self.controller.config.get_plugin_section(self, client.server, None)
        mail_config = yield self.controller.config.get_section('mail', client.server, None)

        if not config.get('registration') == 'true' or not mail_config.get('from'):
            self._msg(client.server, user, 'User registration is disabled.')
            return

        _, user_email_rel = yield self.controller.config.get_value(
            'user.email',
            client.server,
            None,
            nickname
        )
        _, verify_rel = yield self.controller.config.get_value(
            'user.verify',
            client.server,
            None,
            nickname
        )
        if user_email_rel is not None or verify_rel is not None:
            self._msg(client.server, user, 'User %s already exists.' % nickname)
            return

        verification_code = ''
        for i in range(16):
            verification_code += random.choice(string.ascii_letters + string.digits)

        verify_data = {
            'email': email,
            'password': pw_hash,
            'code': verification_code,
        }

        self.controller.config.update_value(
            'user.verify',
            client.server,
            None,
            nickname,
            json.dumps(verify_data),
        )

        msg = MIMEText("""%(nickname)s,

In order to complete your registration you must send the
following command on IRC:
/msg %(mynickname)s verify %(code)s

Kind regards,
%(mynickname)s automailer
""" % {'nickname': nickname, 'mynickname': client.nickname, 'code': verification_code})
        msg['Subject'] = '%s account registration' % client.nickname
        msg['From'] = mail_config['from']
        msg['To'] = email
        sendmail(mail_config.get('mailserver', 'localhost'), mail_config['from'], [email], msg.as_string())

        self._msg(client.server, user, 'An email with verification instructions has been sent.')

    @defer.inlineCallbacks
    def _on_command_verify(self, client, user, verification_code):
        nickname = parse_user(user)[0]

        verify_data, _ = yield self.controller.config.get_value('user.verify', client.server, None, nickname)
        if not verify_data:
            self._msg(client.server, user, 'Please register first.')
            return

        try:
            verify_data = json.loads(verify_data)
        except Exception as e:
            log.err(e, 'Could not decode verification data')
            self._msg(client.server, user, 'Something went terribly wrong.')
            return

        if verify_data['code'] != verification_code:
            self._msg(client.server, user, 'Incorrect verification code. Please double check.')
            return

        self.controller.config.update_value(
            'user.email',
            client.server,
            None,
            nickname,
            verify_data['email'].encode('utf-8'),
        )
        self.controller.config.update_value(
            'user.password',
            client.server,
            None,
            nickname,
            verify_data['password'].encode('utf-8'),
        )

        default_role, _ = yield self.controller.config.get_plugin_value(self, client.server, None, 'default_role')
        if default_role:
            self.controller.config.update_value(
                'user.role',
                client.server,
                None,
                nickname,
                default_role
            )

        self._msg(client.server, user, 'Registration completed.')
