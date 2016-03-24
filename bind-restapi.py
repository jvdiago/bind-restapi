from tornado.ioloop import IOLoop
import tornado.web
import json
from tornado.options import define, options
import os
import sys
import daemon
from subprocess import Popen, PIPE, STDOUT
import shlex

# curl -X DELETE -H 'Content-Type: application/json' -H 'X-Api-Key: secret' -d '{ "hostname": "host.example.com"}' http://localhost:9999/dns
# curl -X POST -H 'Content-Type: application/json' -H 'X-Api-Key: secret' -d '{ "hostname": "host.example.com", "ip": "1.1.1.10" }' http://localhost:9999/dns
# curl -X POST -H 'Content-Type: application/json' -H 'X-Api-Key: secret' -d '{ "hostname": "host.example.com", "ip": "1.1.1.10", "ptr": "yes", "ttl": 86400}' http://localhost:9999/dns

cwd = os.path.dirname(os.path.realpath(__file__))

define('address', default='0.0.0.0', type=str, help='Listen on interface')
define('port', default=9999, type=int, help='Listen on port')
define('pidfile', default=os.path.join(cwd, 'bind-restapi.pid'), type=str, help='PID location')
define('logfile', default=os.path.join(cwd, 'bind-restapi.log'), type=str, help='Log file')
define('ttl', default='8640', type=int, help='Default TTL')
define('nameserver', default='127.0.0.1', type=str, help='Master DNS')
define('sig_key', default=os.path.join(cwd, 'dnnsec_key.private'), type=str, help='DNSSEC Key')
define('secret', default='secret', type=str, help='Protection Header')
define('nsupdate_command', default='nsupdate', type=str, help='nsupdate')

mandatory_create_parameters = ['ip', 'hostname']
mandatory_delete_parameters = ['hostname']

nsupdate_create_template = '''\
server {0}
update add {1} {2} A {3}
send\
'''
nsupdate_create_ptr = '''\
update add {0} {1} PTR {2}
send\
'''
nsupdate_delete_template = '''\
server {0}
update delete {1} A
send
update delete {1} PTR
send\
'''


def auth(func):
    def header_check(self, *args, **kwargs):
        secret_header = self.request.headers.get('X-Api-Key', None)
        if not secret_header or not options.secret == secret_header:
            self.send_error(401, message='X-Api-Key not correct')

        return func(self, *args, **kwargs)
    return header_check


def reverse_ip(ip):
    return '.'.join(reversed(ip.split('.'))) + ".in-addr.arpa"


class JsonHandler(tornado.web.RequestHandler):

    """Request handler where requests and responses speak JSON."""
    def prepare(self):
        # Incorporate request JSON into arguments dictionary.
        if self.request.body:
            try:
                json_data = json.loads(self.request.body)
                self.request.arguments.update(json_data)
            except ValueError:
                message = 'Unable to parse JSON.'
                self.send_error(400, message=message) # Bad Request

    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')

    def write_error(self, status_code, **kwargs):
        reason = self._reason
        if 'message' in kwargs:
            reason = kwargs['message']

        self.finish(json.dumps({'code': status_code, 'message': reason}))


class ValidationMixin():
    def validate_params(self, params):
        for parameter in params:
            if parameter not in self.request.arguments:
                self.send_error(400, message='Parameter %s not found' % parameter)


class MainHandler(ValidationMixin, JsonHandler):

    def _nsupdate(self, update):
        cmd = '{0} -k {1}'.format(options.nsupdate_command, options.sig_key)
        p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        stdout = p.communicate(input=update)[0]
        return p.returncode, stdout.decode()

    @auth
    def post(self):
        self.validate_params(mandatory_create_parameters)

        ip = self.request.arguments['ip']
        hostname = self.request.arguments['hostname']

        ttl = options.ttl
        override_ttl = self.request.arguments.get('ttl')
        if override_ttl:
            ttl = int(override_ttl)

        update = nsupdate_create_template.format(
            options.nameserver,
            hostname,
            ttl,
            ip)

        if self.request.arguments.get('ptr') == 'yes':
            reverse_name = reverse_ip(ip)
            ptr_update = nsupdate_create_ptr.format(
                reverse_name,
                ttl,
                hostname)
            update += '\n' + ptr_update

        return_code, stdout = self._nsupdate(update)
        if return_code != 0:
            self.send_error(500, message=stdout)
        self.send_error(200, message='Record created')

    @auth
    def delete(self):
        self.validate_params(mandatory_delete_parameters)

        hostname = self.request.arguments['hostname']

        update = nsupdate_delete_template.format(
            options.nameserver,
            hostname)
        return_code, stdout = self._nsupdate(update)
        if return_code != 0:
            self.send_error(500, message=stdout)
        self.send_error(200, message='Record deleted')


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/dns", MainHandler)
        ]
        tornado.web.Application.__init__(self, handlers)


class TornadoDaemon(daemon.Daemon):
    def run(self):
        while True:
            app = Application()
            app.listen(options.port, options.address)
            IOLoop.instance().start()

if __name__ == '__main__':
    daemon = TornadoDaemon(options.pidfile, stdout=options.logfile, stderr=options.logfile)

    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            print 'Starting tornado...'
            daemon.start()
        elif 'stop' == sys.argv[1]:
            print 'Stopping tornado...'
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            print 'Restarting tornado...'
            daemon.restart()
        else:
            print 'Unknown command'
            sys.exit(2)
        sys.exit()
    else:
        print 'Usage: %s start|stop|restart' % sys.argv[0]
        sys.exit(2)

