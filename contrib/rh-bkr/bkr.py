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

def sub_dict(diction, keys, default=None):
    r = dict(diction)
    return dict([ (k, r.pop(k, default)) for k in keys ]), r

def nitrate_get_script_name_for_case(case):
    name = case.get('script_name', None)
    if name is None:
        name = case['script'].split('=')[-1]
        case['script_name'] = name
    return name

_nitrate_tags = {}
def nitrate_get_tag_by_id(tag_id):
    if tag_id not in _nitrate_tags:
        tags = nitrate.Nitrate()._server.Tag.get_tags({'ids': [tag_id]})
        if not tags:
            _nitrate_tags[tag_id] = None
        elif len(tags) > 1:
            raise Error("tag with id %d appears more then once: %s" % (tag_id, repr(tags)))
        else:
            _nitrate_tags[tag_id] = tags[0]
    return _nitrate_tags.get(tag_id, None)

_nitrate_tags_searched_name = {}
def nitrate_get_tag_by_name(tag_name):
    if tag_name not in _nitrate_tags_searched_name:
        tags = nitrate.Nitrate()._server.Tag.get_tags({'names': [tag_name]})
        for t in tags:
            _nitrate_tags[t['id']] = t
        _nitrate_tags_searched_name[tag_name] = 1
    tags = [ tag for tag_id, tag in _nitrate_tags.iteritems()  if tag['name'] == tag_name ]
    if not tags:
        return None
    if len(tags) > 1:
        raise Error("tag with name %d appears more then once: %s" % (tag_name, repr(tags)))
    return tags[0]

_nitrate_cases = {}
def _nitrate_add_case(case):
    case_id = case['case_id']
    if case_id in _nitrate_cases:
        case2 = _nitrate_cases[case_id]
        tags = list(sorted(set(case['tag'] + case2['tag'])))
        case2['tag'] = tags
    else:
        _nitrate_cases[case_id] = case

def _nitrate_base_filter(additional=None, default=None):
    # see https://tcms.engineering.redhat.com/plan/6726/networkmanager#treeview
    if default is None:
        # f = {'plan__component__name': 'NetworkManager'}
        f = {'plan__parent_id': '6726'}
    else:
        f = dict(default);

    if additional:
        for key,value in additional.iteritems():
            f[key] = value
    return f

_nitrate_cases_searched_by_tag = {}
def nitrate_get_cases_by_tag(tag=None, tag_name=None, tag_id=None):
    if (0 if tag is None else 1) + \
       (0 if tag_name is None else 1) + \
       (0 if tag_id is None else 1) != 1:
        raise Error("Need one filter argument")
    if tag is None:
        if tag_name is not None:
            tag = nitrate_get_tag_by_name(tag_name)
        if tag_id is not None:
            tag = nitrate_get_tag_by_id(tag_id)
    tag_id = tag['id']
    if not _nitrate_get_cases_all and tag_id not in _nitrate_cases_searched_by_tag:
        cases = nitrate.Nitrate()._server.TestCase.filter(_nitrate_base_filter({'tag' : tag_id}))
        for case in cases:
            _nitrate_add_case(case)
        _nitrate_cases_searched_by_tag[tag_id] = 1
    return [ case for case_id, case in _nitrate_cases.iteritems() if tag_id in case['tag'] ]

_nitrate_get_cases_all = False
def nitrate_get_cases_all():
    global _nitrate_get_cases_all
    if not _nitrate_get_cases_all:
        cases = nitrate.Nitrate()._server.TestCase.filter(_nitrate_base_filter())
        for case in cases:
            _nitrate_add_case(case)
        _nitrate_get_cases_all = True
    return [ case for case_id, case in _nitrate_cases.iteritems() ]


def nitrate_merge_cases(cases, new):
    for case in new:
        cases[case['case_id']] = case

def nitrate_subtract_cases(cases, remove, no_cases=None):
    for case in remove:
        case_id = case['case_id']
        case = cases.get(case_id, None)
        if case is not None:
            del cases[case_id]
            if no_cases is not None:
                no_cases[case_id] = case

def nitrate_cases_get(tags=None, no_tags=None, include_all=False):
    cases = {}
    no_cases = {}

    if isinstance(tags, basestring):
        tags = [tags]
    if isinstance(no_tags, basestring):
        no_tags = [no_tags]

    cases_tag = []
    cases_no_tag = []

    # we have to fetch all the cases by tags esplicitly to merge them properly
    # in our cache.
    if not tags or include_all:
        # only blacklist of ~all~. Fetch first all.
        cases_tag = [ nitrate_get_cases_all() ]
    else:
        cases_tag = [ nitrate_get_cases_by_tag(tag_name=tag) for tag in tags ]
    if no_tags:
        cases_no_tag = [ nitrate_get_cases_by_tag(tag_name=tag) for tag in no_tags ]

    for c in cases_tag:
        nitrate_merge_cases(cases, c)
    for c in cases_no_tag:
        nitrate_subtract_cases(cases, c, no_cases)

    return cases, no_cases

def nitrate_filter_by_status(cases, whitelist=None, blacklist=None):
    cases = _nitrate_index_cases_by_case_id(cases)

    inc = set(cases.keys())
    exc = set()
    if whitelist:
        l = []
        for wl in whitelist:
            l.extend([case_id for case_id, case in cases.iteritems() if case['case_status'] == wl])
        new_inc = inc.intersection(l)
        exc.update(inc.difference(new_inc))
        inc = new_inc
    if blacklist:
        l = []
        for wl in blacklist:
            l.extend([case_id for case_id, case in cases.iteritems() if case['case_status'] == wl])
        new_exc = inc.intersection(l)
        inc.difference_update(new_exc)
        exc.update(new_exc)
    no_cases, cases = sub_dict(cases, exc)
    return cases, no_cases

def _nitrate_index_cases_by_case_id(cases):
    if not isinstance(cases, dict):
        cases = dict([(case['case_id'], case) for case in cases])
    return cases

def _nitrate_index_cases_by_tag_id(cases):
    cases = _nitrate_index_cases_by_case_id(cases)
    by_tag = {}
    for case_id, case in cases.iteritems():
        for tag_id in case['tag']:
            t = by_tag.get(tag_id, None)
            if t is None:
                t = {}
                by_tag[tag_id] = t
            t[case_id] = case
    t2 = {}
    for tag_id, t in by_tag.iteritems():
        l = list(t.values())
        by_tag[tag_id] = l
        t2[nitrate_get_tag_by_id(tag_id)['name']] = l
    return t2, by_tag


def nitrate_print_cases(cases, prefix=""):
    cases = _nitrate_index_cases_by_case_id(cases)
    tags = {}
    for case_id in sorted(cases.keys(), key=lambda i: (tuple(sorted(cases[i]["plan"])), i)):
        case = cases[case_id]
        t = case.get('tag_names', None)
        if t is None:
            tag_ids = tuple(case['tag'])
            t = tags.get(tag_ids, None)
            if t is None:
                t = ','.join(sorted(set([nitrate_get_tag_by_id(tag_id)['name']  for tag_id in tag_ids])))
                tags[tag_ids] = t
            case['tag_names'] = t
        print("%s[%10s/%7d] = %-60s - %-20s - [ %s %s]" % (prefix, \
            ",".join([str(i) for i in sorted(case["plan"])]),
            case_id,
            nitrate_get_script_name_for_case(case), case['case_status'], \
            t, "(?) " if not _nitrate_get_cases_all else ""))

def nitrate_get_cases_by_one_tag(tag_name):
    tag = nitrate_get_tag_by_name(tag_name)
    cases = nitrate_get_cases_all()
    cases_with_tag = nitrate_get_cases_by_tag(tag)
    cases = _nitrate_index_cases_by_case_id(cases)
    cases_with_tag = _nitrate_index_cases_by_case_id(cases_with_tag)
    return sub_dict(cases, cases_with_tag.keys())

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
            self.pattern = '/NetworkManager(-adsl|-bluetooth|-debuginfo|-devel|-glib|-glib-devel|-tui|-wifi|-wwan)?-[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-.*\.x86_64\.rpm'
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
        self.parser.add_argument('--nitrate-tag', '-t', action='append', help='Query nitrate for tests having this tag. Output is appended to $TESTS. Specifying more then once combines them as AND')
        self.parser.add_argument('--nitrate-all', '-a', action='store_true', help='Query all nitrate tests')
        self.parser.add_argument('--nitrate-exclude-tag', '-T', action='append', help='Query nitrate for tests not having this tag. Output is appended to $TESTS. In combination with --nitrate-tag this blacklists cases (after selecting then)')
        self.parser.add_argument('--nitrate-status', '-s', action='append', help='After selecting the tests by via --nitrate-tag, --nitrate-all, or --nitrate-exclude-tag, further whitelist by status')
        self.parser.add_argument('--nitrate-exclude-status', '-S', action='append', help='After selecting the tests by via --nitrate-tag, --nitrate-all, --nitrate-exclude-tag, further blacklist by status')
        self.parser.add_argument('--tests', '-c', action='append', help='Append argument to $TESTS')
        self.parser.add_argument('--job', '-j', help='beaker xml job file')
        self.parser.add_argument('--verbose', '-v', action='count', help='print more information')

    def _prepare_rpms(self):
        if self.options.rpm is None:
            self.rpm = None
            return
        self.rpm = []
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
        if self.rpm is not None:
            self.subs['RPM_LIST'] = [ u for x in self.rpm for u in x[1].url() ]

        tests = []
        if self.options.tests:
            tests.extend(self.options.tests)
        if self.options.nitrate_all or self.options.nitrate_tag or self.options.nitrate_exclude_tag:

            cases, no_cases = nitrate_cases_get(self.options.nitrate_tag, self.options.nitrate_exclude_tag, self.options.nitrate_all)
            cases, no_case_by_status = nitrate_filter_by_status(cases, self.options.nitrate_status, self.options.nitrate_exclude_status)

            if self.options.verbose >= 1:
                if self.options.nitrate_exclude_tag:
                    print("Blacklisted %d cases for tags %s..." % (len(no_cases), sorted(set(self.options.nitrate_exclude_tag))))
                nitrate_print_cases(no_cases, prefix="  - ")
                if self.options.nitrate_status or self.options.nitrate_exclude_status:
                    print("Excluded %d cases after %s%s%s" % (len(no_case_by_status), \
                            (("--nitrate-status=" + ",".join(self.options.nitrate_status)) if self.options.nitrate_status else ""), \
                            (" and " if (self.options.nitrate_status and self.options.nitrate_exclude_status) else ""), \
                            (("--nitrate-exclude-status=" + ",".join(self.options.nitrate_exclude_status)) if self.options.nitrate_exclude_status else "")))
                nitrate_print_cases(no_case_by_status, prefix="  - ")
                if self.options.nitrate_tag:
                    print("Selected %d cases for tags %s..." % (len(cases), sorted(set(self.options.nitrate_tag))))
                else:
                    print("Selected %d cases..." % (len(cases)))
                nitrate_print_cases(cases, prefix="  + ")
            tests.extend([nitrate_get_script_name_for_case(case) for case_id, case in cases.iteritems()])
        elif self.options.nitrate_status or self.options.nitrate_exclude_status:
            raise Exception("--nitrate-status or --nitrate-exclude-status makes only sense with selecting nitrate tags")

        self.subs['TESTS'] = ','.join(sorted(set(tests)))

        for (k,v) in self.subs.iteritems():
            self._print_substitution(k, v)

    DefaultReplacements = {
            'WHITEBOARD'        : 'Test NetworkManager',
            'DISTRO_FAMILY'     : 'RedHatEnterpriseLinux7',
            'DISTRO_VARIANT'    : 'Workstation',
            'DISTRO_NAME'       : 'RHEL-7.0-20140502.n.0',
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

        if self.rpm:
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
                    print("     https://beaker.engineering.redhat.com/jobs/mine");

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
