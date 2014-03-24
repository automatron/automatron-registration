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

    def on_command(self, server, user, command, args):
        config = self.command_map.get(command)
        if config is None:
            return

        if not config[1] <= len(args) <= config[2]:
            self._msg(server['server'], user, 'Invalid syntax. Use: %s %s' % (command, config[0]))
        else:
            getattr(self, '_on_command_%s' % command)(server, user, *args)
        return STOP

    @defer.inlineCallbacks
    def _on_command_identify(self, server, user, channel=None):
        username, username_rel = yield self.controller.config.get_username_by_hostmask(server['server'], user)
        if username is not None:
            if username_rel == 0:
                identity = 'You are globally known as %s' % username
            else:
                identity = 'You are known as %s' % username

            role, role_rel = yield self.controller.config.get_role_by_username(server['server'], channel, username)
            if role_rel is not None and role_rel < username_rel:
                role = role_rel = None

            if role_rel is None:
                self._msg(server['server'], user, identity)
            elif role_rel in (2, 3):
                self._msg(server['server'], user, '%s and your role in %s is %s' % (identity, channel, role))
            else:
                self._msg(server['server'], user, '%s and your role is %s' % (identity, role))
        else:
            self._msg(server['server'], user, 'I don\'t know you...')

    @defer.inlineCallbacks
    def _on_command_register(self, server, user, password, email):
        nickname = parse_user(user)[0]
        pw_hash = pwd_context.encrypt(password)

        config = yield self.controller.config.get_plugin_section(self, server['server'], None)
        mail_config = yield self.controller.config.get_section('mail', server['server'], None)

        if not config.get('registration') == 'true' or not mail_config.get('from'):
            self._msg(server['server'], user, 'User registration is disabled.')
            return

        _, user_email_rel = yield self.controller.config.get_value(
            'user.email',
            server['server'],
            None,
            nickname
        )
        _, verify_rel = yield self.controller.config.get_value(
            'user.verify',
            server['server'],
            None,
            nickname
        )
        if user_email_rel is not None or verify_rel is not None:
            self._msg(server['server'], user, 'User %s already exists.' % nickname)
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
            server['server'],
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
""" % {'nickname': nickname, 'mynickname': server['nickname'], 'code': verification_code})
        msg['Subject'] = '%s account registration' % server['nickname']
        msg['From'] = mail_config['from']
        msg['To'] = email
        sendmail(mail_config.get('mailserver', 'localhost'), mail_config['from'], [email], msg.as_string())

        self._msg(server['server'], user, 'An email with verification instructions has been sent.')

    @defer.inlineCallbacks
    def _on_command_verify(self, server, user, verification_code):
        nickname = parse_user(user)[0]

        verify_data, _ = yield self.controller.config.get_value('user.verify', server['server'], None, nickname)
        if not verify_data:
            self._msg(server['server'], user, 'Please register first.')
            return

        try:
            verify_data = json.loads(verify_data)
        except Exception as e:
            log.err(e, 'Could not decode verification data')
            self._msg(server['server'], user, 'Something went terribly wrong.')
            return

        if verify_data['code'] != verification_code:
            self._msg(server['server'], user, 'Incorrect verification code. Please double check.')
            return

        self.controller.config.update_value(
            'user.email',
            server['server'],
            None,
            nickname,
            verify_data['email'].encode('utf-8'),
        )
        self.controller.config.update_value(
            'user.password',
            server['server'],
            None,
            nickname,
            verify_data['password'].encode('utf-8'),
        )

        default_role, _ = yield self.controller.config.get_plugin_value(self, server['server'], None, 'default_role')
        if default_role:
            self.controller.config.update_value(
                'user.role',
                server['server'],
                None,
                nickname,
                default_role
            )

        self._msg(server['server'], user, 'Registration completed.')
