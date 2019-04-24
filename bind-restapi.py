from tornado.ioloop import IOLoop
import tornado.web
import json
from tornado.options import define, options
import os
import sys
import daemon
from subprocess import Popen, PIPE, STDOUT
import shlex

# curl -X DELETE -H 'Content-Type: application/json' -H 'X-Api-Key: secret' -d '{ "hostname": "host.example.com", "view": "none"}' http://localhost:9999/dns
# curl -X POST -H 'Content-Type: application/json' -H 'X-Api-Key: secret' -d '{ "hostname": "host.example.com", "view": "none", "method": "a", "ip": "1.1.1.10", "ttl": 86400}' http://localhost:9999/dns
# curl -X POST -H 'Content-Type: application/json' -H 'X-Api-Key: secret' -d '{ "hostname": "host.example.com", "view": "none", "method": "ptr", "ip": "1.1.1.10", "ttl": 86400}' http://localhost:9999/dns
# curl -X POST -H 'Content-Type: application/json' -H 'X-Api-Key: secret' -d '{ "hostname": "host.example.com", "view": "none", "method": "cname", "cname": "www.example.com", "ttl": 86400}' http://localhost:9999/dns

cwd = os.path.dirname(os.path.realpath(__file__))
global json_sig_key

define('address', default='0.0.0.0', type=str, help='Listen on interface')
define('port', default=9999, type=int, help='Listen on port')
define('pidfile', default=os.path.join(cwd, 'bind-restapi.pid'), type=str, help='PID location')
define('logfile', default=os.path.join(cwd, 'bind-restapi.log'), type=str, help='Log file')
define('ttl', default='8640', type=int, help='Default TTL')
define('nameserver', default='127.0.0.1', type=str, help='Master DNS')
define('sig_key', '{"none":"12345"}', type=str, help='DNSSEC Key')
define('secret', default='secret', type=str, help='Protection Header')
define('nsupdate_command', default='nsupdate', type=str, help='nsupdate')

mandatory_create_parameters = ['method', 'hostname', 'view']
mandatory_delete_parameters = ['hostname', 'view']

nsupdate_create_a = '''\
server {0}
update add {1} {2} A {3}
send\n\
'''
nsupdate_create_ptr = '''\
server {0}
update add {1} {2} PTR {3}
send\n\
'''
nsupdate_create_cname = '''\
server {0}
update add {1} {2} CNAME {3}
send\n\
'''
nsupdate_delete_template = '''\
server {0}
update delete {1} A
send
update delete {1} PTR
send
update delete {1} CNAME
send\n\
'''

def auth(func):
    def header_check(self, *args, **kwargs):
        secret_header = self.request.headers.get('X-Api-Key', None)
        if not secret_header or not options.secret == secret_header:
            message='{"error": "X-Api-Key not correct"}'
            self.send_error(401, message=message)

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
                message = '{"error": "Unable to parse JSON."}'
                self.send_error(400, message=message) # Bad Request

    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')

    def write_error(self, status_code, **kwargs):
        if 'message' in kwargs:
            reason = kwargs['message']

            self.finish(json.dumps({'code': status_code, 'message': reason}))


class ValidationMixin():
    def validate_params(self, params):
        for parameter in params:
            if parameter not in self.request.arguments:
                message='{"error": "Parameter {0} not found"}'.format(parameter)
                self.send_error(400, message=message)


class MainHandler(ValidationMixin, JsonHandler):

    def _nsupdate(self, update, view):
        if not view in json_sig_key:
            return 1, "No this view named: " + view

        key = json_sig_key[view]
        cmd = '{0} -y \"{1}:{2}\"'.format(options.nsupdate_command, view, key)
        p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        stdout = p.communicate(input=update)[0]
        return p.returncode, stdout.decode()

    def _split_nameserver(self, server):
       return server.split(',')

    @auth
    def post(self):
        self.validate_params(mandatory_create_parameters)
        hostname = self.request.arguments['hostname']
        view = self.request.arguments['view']
        ttl = options.ttl
        override_ttl = self.request.arguments.get('ttl')
        if override_ttl:
            ttl = int(override_ttl)

        nameservers = self._split_nameserver(options.nameserver)
        method = self.request.arguments['method']
        result = {}
        result_code = 200

        if method == 'a':
            ip = self.request.arguments['ip']
            for server in nameservers:
                update = nsupdate_create_a.format(
                    server,
                    hostname,
                    ttl,
                    ip)
                code, stdout = self._nsupdate(update, view)
                if code == 0:
                    result[server] = "Record created"
                else:
                    result[server] = stdout
                    result_code = 500

        elif method == 'ptr':
            ip = self.request.arguments['ip']
            reverse_name = reverse_ip(ip)
            for server in nameservers:
                update = nsupdate_create_ptr.format(
                    server,
                    reverse_name,
                    ttl,
                    hostname)
                code, stdout = self._nsupdate(update, view)
                if code == 0:
                    result[server] = "Record created"
                else:
                    result[server] = stdout
                    result_code = 500

        elif method == 'cname':
            cname = self.request.arguments['cname']
            for server in nameservers:
                update = nsupdate_create_cname.format(
                    server,
                    hostname,
                    ttl,
                    cname)
                code, stdout = self._nsupdate(update, view)
                if code == 0:
                    result[server] = "Record created"
                else:
                    result[server] = stdout
                    result_code = 500

        else:
            result['error'] = "Not support the method: {0}".format(method)
            result_code = 500

        self.send_error(result_code, message=result)

    @auth
    def delete(self):
        self.validate_params(mandatory_delete_parameters)

        hostname = self.request.arguments['hostname']
        view = self.request.arguments['view']

        nameservers = self._split_nameserver(options.nameserver)
        result = {}
        result_code=200
        for server in nameservers:
            update = nsupdate_delete_template.format(
                    server,
                    hostname)
            code, stdout = self._nsupdate(update, view)
            if code == 0:
                result[server] = "Record deleted"
            else:
                result[server] = stdout
                result_code = 500

        self.send_error(result_code, message=result)


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
    # Read config file
    if os.path.isfile("./config"):
        tornado.options.parse_config_file("./config") 
    elif os.path.isfile("./bind-restapi.conf"):
        tornado.options.parse_config_file("./bind-restapi.conf")
    elif os.path.isfile("/etc/bind-restapi.conf"):
        tornado.options.parse_config_file("/etc/bind-restapi.conf")

    # Analysis sig key
    if options.sig_key:
        try:
            json_sig_key = json.loads(options.sig_key)
        except ValueError:
            print 'Unable to parse sig key, it must be json.'
            sys.exit(2)

    # Start daemon
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

