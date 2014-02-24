#!/usr/bin/env python

import sys
import argparse
import subprocess
import os
import re
import kobo.xmlrpc
import xmlrpclib
import termcolor
import os
import tempfile
import datetime
import random
import string
import urllib
import glob
import uuid
import nitrate
import sets


devnull = open(os.devnull, 'w')
timestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S');

def id_generator(size=6, chars=string.ascii_lowercase + string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))

def is_sequence(arg):
    return (not hasattr(arg, "strip") and
            hasattr(arg, "__getitem__") or
            hasattr(arg, "__iter__"))

def seq_unique(seq):
    s = sets.Set()
    for i in seq:
        if i not in s:
            s.add(i)
            yield i

_nitrate_tag = {}
def nitrate_tag(tag):
    if tag not in _nitrate_tag:
        testcases = nitrate.Nitrate()._server.TestCase.filter({'plan__component__name': 'NetworkManager', 'tag__name' : tag})
        _nitrate_tag[tag] = [ case['script'].split('=')[-1] for case in testcases if case['script'] ]
    return _nitrate_tag[tag]

def _call(args, stderr=devnull, reason=None, dry_run=False, verbose=False):
    if verbose:
        print(">%s '%s'" % ('x' if dry_run else '>',  "' '".join(args)))
    try:
        if dry_run:
            output = ''
        else:
            output = subprocess.check_output(args, stderr=stderr)
    except subprocess.CalledProcessError, e:
        print "Error invoking command for %s: %s" % (reason, ' '.join(args))
        print ''.join(['++ ' + x + '\n' for x in e.output.splitlines()])
        sys.exit("invoking command failed");
    return output

_kinit_user = None
def kinit_user():
    global _kinit_user
    if _kinit_user is None:
        user = None
        out = _call(['klist'], stderr=subprocess.STDOUT, reason='check kerberos user')
        o = out.splitlines()
        if len(o) >= 2:
            m = re.match(r'^.*: ([a-zA-Z_0-9-]+)@.*$', o[1])
            if m:
                user = m.group(1)
        if user is None:
            print("klist did not show a valid kerberos ticket:")
            print ''.join(['>> ' + x + '\n' for x in o])
            sys.exit("No kerberos ticket")
        _kinit_user = user
    return _kinit_user

class UploadFile:
    def __init__(self, uri):
        self.uri = uri
    def url(self):
        raise NotImplementedError("not implemented")
    def prepare(self, dry_run):
        raise NotImplementedError("not implemented")
class UploadFileUrl(UploadFile):
    def __init__(self, uri):
        UploadFile.__init__(self, uri)
    def url(self):
        return [self.uri]
    def prepare(self, dry_run):
        pass
class UploadFileSsh(UploadFile):
    user = kinit_user()
    host = 'file.brq.redhat.com'
    def __init__(self, uri):
        UploadFile.__init__(self, uri)
        if uri.startswith('file://'):
            uri = uri[len('file://'):]
            self.files = [f for f in glob.glob(uri) if os.path.isfile(f)]
        else:
            if not os.path.isfile(uri):
                raise Exception("RPM '%s' is not a valid file" % uri)
            self.files = [uri]
        if len(self.files) <= 0:
            raise Exception("The pattern '%s' did not match any files" % self.uri)

        self.tag = id_generator()
        self.directory = 'bkr-%s-%s' % (timestamp, self.tag)
        self.dst = "%s@%s:~/public_html/%s/" % (self.user, UploadFileSsh.host, self.directory)
        self.urls = ['http://%s/~%s/%s/%s' % (UploadFileSsh.host, self.user, self.directory, os.path.basename(f)) for f in self.files]
    def url(self):
        return self.urls
    def prepare(self, dry_run):
        for i in range(0, len(self.files)-1):
           print("Uploading file '%s' to %s ( %s )" % (self.files[i], UploadFileSsh.host, self.urls[i]))
        args = ['rsync', '-va'] + self.files + [ self.dst]
        out = _call(args, stderr=subprocess.STDOUT, reason='upload file', dry_run=dry_run, verbose=True);
        for l in out.splitlines():
            print('++ ' + l)
class UploadFileJenkins(UploadFile):
    jenkins_base_url = 'http://10.34.131.51:8080/job/NetworkManager/'
    def __init__(self, uri):
        UploadFile.__init__(self, uri)
        m = re.match('^jenkins://([0-9]+)(/(.+)|/?)?$', uri)
        if not m:
            raise Exception("Error detecting uri scheme jenkins:// from '%s'. Expected is 'jenkins://[ID]/[regex-wildcard]" % uri)
        self.jid = int(m.group(1))
        self.pattern = m.group(3)
        if not self.pattern:
            self.pattern = '/NetworkManager(-glib)?-[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-.*\.x86_64\.rpm'
        try:
            re.match(self.pattern, '')
        except:
            raise Exception("Error in uri scheme '%s': expects a valid regular expression" % uri)

        mainpage = '%s%d/' % (UploadFileJenkins.jenkins_base_url, self.jid)
        urls = []
        p = urllib.urlopen(mainpage)
        page = p.read()
        p.close()
        for a in re.finditer('href=[\'"](artifact/[^\'"]+)[\'"]', page):
            m = re.match('^artifact/.*' + self.pattern + '.*$', a.group(1))
            if m:
                u = mainpage + m.group(0)
                if not u.endswith('/*fingerprint*/') and \
                   not u.endswith('/*view*/'):
                    urls.append(u)
        if not urls:
            raise Exception("Could not detect any URLs on jenkins for '%s' (see %s%s/)" % (self.uri, UploadFileJenkins.jenkins_base_url, self.jid))
        self.urls = urls
    def url(self):
        return self.urls
    def prepare(self, dry_run):
        pass

class CmdBase:
    def __init__(self, name):
        self.name = name
        self.parser = None

    def run(self, argv):
        print_usage()

class CmdSubmit(CmdBase):

    def __init__(self, name):
        CmdBase.__init__(self, name)

        self.parser = argparse.ArgumentParser(prog=sys.argv[0] + " " + name, description='Submit job to beaker.')
        self.parser.add_argument('--no-test', action='store_true', help='do submit the job to beaker')
        self.parser.add_argument('--rpm', '-r', action='append')
        self.parser.add_argument('--nitrate-tag', '-t', action='append')
        self.parser.add_argument('--job', '-j', help='beaker xml job file')

    def _prepare_rpms(self):
        self.rpm = []
        if self.options.rpm is None:
            return
        for r in self.options.rpm:
            if r.startswith('http://') or r.startswith('https://'):
                self.rpm.append((r, UploadFileUrl(r)));
            elif r.startswith('jenkins://'):
                self.rpm.append((r, UploadFileJenkins(r)))
            else:
                self.rpm.append((r, UploadFileSsh(r)))

    def _print_substitution(self, k, v):
        if is_sequence(v):
            print("$%s = [" % (k))
            for s in v:
                print("        %s" % (s))
            print("    ]")
        else:
            print("$%s = %r" % (k, v))
    def _prepare_substitutions(self):
        self.subs = {}
        self.subs['RPM_LIST'] = [ u for x in self.rpm for u in x[1].url() ]

        tests = []
        if self.options.nitrate_tag:
            tests = [ tag for n_tag in self.options.nitrate_tag for tag in nitrate_tag(n_tag) ]
        self.subs['TESTS'] = ','.join(seq_unique(tests))

        for (k,v) in self.subs.iteritems():
            self._print_substitution(k, v)

    DefaultReplacements = {
            'WHITEBOARD'        : 'Test NetworkManager',
            'DISTRO_FAMILY'     : 'RedHatEnterpriseLinux7',
            'DISTRO_VARIANT'    : 'Workstation',
            'DISTRO_NAME'       : 'RHEL-7.0-20131122.0',
            'DISTRO_METHOD'     : 'nfs',
            'DISTRO_ARCH'       : 'x86_64',
            'TEST_URL'          : 'http://download.eng.brq.redhat.com/scratch/vbenes/NetworkManager-rhel-7.tar.gz',
            'UUID'              : str(uuid.uuid4()),
        }
    def _process_line_get(self, key, replacement, index=None, none=None):
        if key in replacement:
            return replacement[key]
        if not key in self.subs:
            v = os.environ.get(key)
            if v is None:
                if not key in CmdSubmit.DefaultReplacements:
                    replacement[key] = None
                    return none
                v = CmdSubmit.DefaultReplacements[key]
        else:
            v = self.subs[key];
            if is_sequence(v):
                if index is not None and index != '@':
                    raise Exception("Using index %s is not implemented" % index)
                v = ' '.join(v)
        replacement[key] = v
        return v

    re_subs0 = re.compile('^(?P<prefix>[^$]*)(?P<rest>\$.*\n?)$')
    re_subs1 = re.compile('^\$(?P<name>\$|(?P<name0>[a-zA-Z_]+)|{(?P<name1>[a-zA-Z_]+)(\[(?P<index1>[0-9]+|@)\])?})(?P<rest>.*\n?$)')
    def _process_line(self, l, replacements):

        r = ''
        while True:
            m = CmdSubmit.re_subs0.match(l)
            if m is None:
                return r + l
            r = r + m.group('prefix')
            l = m.group('rest')
            m = CmdSubmit.re_subs1.match(l)
            if m is None:
                return r + l
            name = m.group('name')
            if name == '$':
                r = r + '$'
            elif m.group('name0'):
                r = r + self._process_line_get(m.group('name0'), replacements, none='')
            elif m.group('name1'):
                r = r + self._process_line_get(m.group('name1'), m.group('index1'), replacements, none='')
            else:
                r = r + '$' + name
            l = m.group('rest')
            if not l:
                return r

    def run(self, argv):
        self.options = self.parser.parse_args(argv)

        if self.options.job:
            with open(self.options.job) as f:
                job0 = list(f)

        self._prepare_rpms()
        self._prepare_substitutions()

        if self.options.job:
            job = []
            replacements = {}
            for l in job0:
                job.append(self._process_line(l, replacements))
            for (k,v) in [ (k,v) for (k,v) in replacements.iteritems() if v is not None ]:
                print("replace \'%s\' => '%s'" % (k, v))
            for k in [ k for (k,v) in replacements.iteritems() if v is None ]:
                print("replace \'%s\' %s" % (k, termcolor.colored("not found", 'yellow')))
            temp = tempfile.NamedTemporaryFile(prefix='brk_job.xml.', delete=False)
            for l in job:
                temp.write(l)
            temp.close()

            print("Write job '%s' to file '%s'" % (self.options.job, temp.name));

        for r in self.rpm:
            r[1].prepare(dry_run=not self.options.no_test)

        if self.options.job:
            args = ['bkr', 'job-submit', temp.name]
            if not self.options.no_test:
                out = _call(args, dry_run=True, verbose=True)
            else:
                out = _call(args, dry_run=False, verbose=True)
                print("Job successfully submitted: " + out)
                m = re.match('.*J:([0-9]+).*', out)
                if m:
                    print("URL: https://beaker.engineering.redhat.com/jobs/%s" % (m.group(1)))

class CmdHelp(CmdBase):

    def __init__(self, name):
        CmdBase.__init__(self, name)

    def run(self, argv):
        print_usage()
        if len(argv) >= 1:
            commands = find_cmds_by_name(argv[0])
            if len(commands) == 1:
                parser = commands[0].parser
                if parser:
                   print
                   parser.print_help()


if __name__ == "__main__":

    commands = {}
    def commands_add(name, t, realname=None):
        commands[name] = t(realname if realname else name)


    commands_add('submit',      CmdSubmit)
    commands_add('help',        CmdHelp)
    commands_add('?',           CmdHelp, realname='help')


    def find_cmds_by_name(command_name):
        return list([commands[cmd] for cmd in commands.keys() if cmd.startswith(command_name)])

    def print_usage():
        print("%s [%s] [OPTIONS]" % (sys.argv[0], '|'.join(commands.keys())))

    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
    commands_matches = find_cmds_by_name(sys.argv[1])
    if len(commands_matches) == 0:
        print("Invalid command \"%s\". Try one of [ %s ]" % (sys.argv[1], ', '.join(commands.keys())))
        print_usage();
        sys.exit(1)
    elif len(commands_matches) > 1:
        print("Invalid command \"%s\". Not exact match of [ %s ]" % (sys.argv[1], ', '.join(commands.keys())))
        print_usage();
        sys.exit(1)
    else:
        commands_matches[0].run(sys.argv[2:])
