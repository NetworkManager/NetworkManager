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
        name = case['script']
        if name is None:
            if '__script_name_hack' not in case:
                print("WARNING: test case has no script name. It cannot be used: %s" % (str(case)))
                case['__script_name_hack'] = ''
            return ""
        name = name.split('=')[-1]
        case['script_name'] = name
    return name

_nitrate_tags = {}
def nitrate_get_tag_by_id(tag_id, fail_on_not_exists=False):
    if tag_id not in _nitrate_tags:
        tags = nitrate.Nitrate()._server.Tag.get_tags({'ids': [tag_id]})
        if not tags:
            _nitrate_tags[tag_id] = None
        elif len(tags) > 1:
            raise Error("tag with id %d appears more then once: %s" % (tag_id, repr(tags)))
        else:
            _nitrate_tags[tag_id] = tags[0]
    t = _nitrate_tags.get(tag_id, None)
    if fail_on_not_exists and t is None:
        raise Exception("Tag with id='%s' does not exist" % (tag_id))
    return t

_nitrate_tags_searched_name = {}
def nitrate_get_tag_by_name(tag_name, fail_on_not_exists=False):
    if tag_name not in _nitrate_tags_searched_name:
        tags = nitrate.Nitrate()._server.Tag.get_tags({'names': [tag_name]})
        for t in tags:
            _nitrate_tags[t['id']] = t
        _nitrate_tags_searched_name[tag_name] = 1
    tags = [ tag for tag_id, tag in _nitrate_tags.iteritems()  if tag['name'] == tag_name ]
    t = None
    if tags:
        if len(tags) > 1:
            raise Error("tag with name %d appears more then once: %s" % (tag_name, repr(tags)))
        t = tags[0]
    if fail_on_not_exists and t is None:
        raise Exception("Tag with name='%s' does not exist" % (tag_name))
    return t

_nitrate_cases = {}
def _nitrate_add_case(case, tag_id=None):
    case_id = case['case_id']
    tags = None
    if case_id in _nitrate_cases:
        case2 = _nitrate_cases[case_id]
        tags = case['tag'] + case2['tag']
        case = case2
    else:
        _nitrate_cases[case_id] = case
    if tag_id is not None:
        if tags is None:
            tags = [tag_id]
        else:
            tags.append(tag_id)
    if tags is not None:
        case['tag'] = list(sorted(set(tags)))

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
            tag = nitrate_get_tag_by_name(tag_name, True)
        if tag_id is not None:
            tag = nitrate_get_tag_by_id(tag_id, True)

    tag_id = tag['id']
    if tag_id not in _nitrate_cases_searched_by_tag:
        cases = nitrate.Nitrate()._server.TestCase.filter(_nitrate_base_filter({'tag' : tag_id}))
        for case in cases:
            _nitrate_add_case(case, tag_id)
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
    if not tags:
        cases_tag = []
    else:
        cases_tag = [ nitrate_get_cases_by_tag(tag_name=tag) for tag in tags ]
    if include_all:
        # only blacklist of ~all~. Fetch first all.
        cases_tag.append(nitrate_get_cases_all())
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
        t2[nitrate_get_tag_by_id(tag_id, True)['name']] = l
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
                t = ','.join(sorted(set([nitrate_get_tag_by_id(tag_id, True)['name']  for tag_id in tag_ids])))
                tags[tag_ids] = t
            case['tag_names'] = t
        print("%s[%10s/%7d] = %-60s - %-20s - [ %s %s]" % (prefix, \
            ",".join([str(i) for i in sorted(case["plan"])]),
            case_id,
            nitrate_get_script_name_for_case(case), case['case_status'], \
            t, "(?) " if not _nitrate_get_cases_all else ""))

def nitrate_get_cases_by_one_tag(tag_name):
    tag = nitrate_get_tag_by_name(tag_name, True)
    cases = nitrate_get_cases_all()
    cases_with_tag = nitrate_get_cases_by_tag(tag)
    cases = _nitrate_index_cases_by_case_id(cases)
    cases_with_tag = _nitrate_index_cases_by_case_id(cases_with_tag)
    return sub_dict(cases, cases_with_tag.keys())

def _call(args, stderr=None, reason=None, dry_run=False, verbose=False):
    if verbose:
        print(">%s '%s'" % ('x' if dry_run else '>',  "' '".join(args)))
    elif stderr is None:
        stderr = devnull
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
    def init(self):
        pass
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
class UploadFile_ParseWebsite(UploadFile):
    def __init__(self, uri):
        self._pattern = None
        self._urls = None
        UploadFile.__init__(self, uri)

    DefaultPattern = '^.*/NetworkManager(-adsl|-bluetooth|-config-connectivity-fedora|-debuginfo|-glib|-libnm|-team|-tui|-wifi|-wwan)?-[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?-[^ /]*\.x86_64\.rpm$'
    @property
    def pattern(self):
        if self._pattern is not None:
            return self._pattern
        return UploadFile_ParseWebsite.DefaultPattern
    def set_pattern(self, value):
        if not value:
            self._pattern = None
        else:
            try:
                re.match(value, '')
            except:
                raise Exception("Error in uri scheme '%s': expects a valid regular expression" % uri)
            self._pattern = value

    @property
    def pattern_is_default(self):
        return self._pattern is None
    def is_matching_url(self, url):
        if re.match('^.*/([^/]+\.(src|x86_64)\.rpm)$', url):
            if re.search(self.pattern, url):
                return True
        return False

    def init(self):
        if self._urls is not None:
            return
        self.parse_uri()

        p = urllib.urlopen(self._mainpage)
        page = p.read()
        p.close()

        if re.match('.*\.gz$', self._mainpage):
            import gzip, StringIO
            p = StringIO.StringIO(page)
            page = gzip.GzipFile(fileobj=p).read()
            p.close()

        urls = list(self.parse_urls(page))
        if not urls:
            self.raise_no_urls()
        self._urls = urls

    def url(self):
        self.init()
        return self._urls

    def prepare(self, dry_run):
        self.init()
        pass

class UploadFileJenkins(UploadFile_ParseWebsite):
    jenkins_base_url = 'http://10.34.130.105:8080/job/NetworkManager/'
    def __init__(self, uri):

        p = urllib.urlopen(self._mainpage)
        page = p.read()
        p.close()

        UploadFile_ParseWebsite.__init__(self, uri)
    def parse_uri(self):
        m = re.match('^jenkins://([0-9]+)(/(.+)|/?)?$', self.uri)
        if not m:
            raise Exception("Error detecting uri scheme jenkins:// from '%s'. Expected is 'jenkins://[ID]/[regex-wildcard]" % (self.uri))
        self._id = int(m.group(1))
        self.set_pattern(m.group(3))
        self._mainpage = '%s%d/' % (UploadFileJenkins.jenkins_base_url, self._id)
    def parse_urls(self, page):
        for a in re.finditer('href=[\'"](artifact/[^\'"]*\.rpm)[\'"]', page):
            url = self._mainpage + a.group(1)
            if self.is_matching_url(url):
                yield url
    def raise_no_urls(self):
        raise Exception("Could not detect any URLs on jenkins for '%s' (see %s%s/)" % (self.uri, UploadFileJenkins.jenkins_base_url, self._id))

class UploadFileBrew(UploadFile_ParseWebsite):
    brew_base_url = 'https://brewweb.devel.redhat.com/'
    def __init__(self, uri):
        UploadFile_ParseWebsite.__init__(self, uri)
    def parse_uri(self):
        if self.uri.startswith('brew://'):
            self._type = "brew"
        elif self.uri.startswith('brewtask://'):
            self._type = "brewtask"
        else:
            raise Exception("Unexpected URI %s" % (self.uri))

        if self._type == "brew":
            m = re.match('^brew://([0-9]+)(/(.+)|/?)?$', self.uri)
        elif self._type == "brewtask":
            m = re.match('^brewtask://([0-9]+)(/(.+)|/?)?$', self.uri)
        if not m:
            raise Exception("Error detecting uri scheme %s:// from '%s'. Expected is '%s://[ID]/[regex-wildcard]" % (self._type, self.uri, self._type))
        self._id = int(m.group(1))
        self.set_pattern(m.group(3))
        if self._type == "brew":
            self._mainpage = '%sbuildinfo?buildID=%s' % (UploadFileBrew.brew_base_url, self._id)
        elif self._type == "brewtask":
            self._mainpage = '%staskinfo?taskID=%s' % (UploadFileBrew.brew_base_url, self._id)
    def parse_urls(self, page):
        if self._type == "brew":
            p = 'href=[\'"](http://download.devel.redhat.com/brewroot/packages/[^\'"]*\.rpm)[\'"]'
        elif self._type == "brewtask":
            p = 'href=[\'"](http://download.devel.redhat.com/brewroot/work/tasks/[^\'"]*\.rpm)[\'"]'

        for a in re.finditer(p, page):
            url = a.group(1)
            if self.is_matching_url(url):
                yield url
    def raise_no_urls(self):
        if self.pattern_is_default:
            raise Exception("Could not detect any URLs on brew for '%s' (see \"%s\"). Try giving a pattern \"%s://%s/.*\"" % (self.uri, self._mainpage, self._type, self._id))
        raise Exception("Could not detect any URLs on brew for '%s' (see \"%s\")" % (self.uri, self._mainpage))

class UploadFileRepo(UploadFile_ParseWebsite):
    def __init__(self, uri):
        UploadFile_ParseWebsite.__init__(self, uri)
    def parse_uri(self):
        m = re.match('^repo:(.+?)/?([^\/]+rpm)?$', self.uri)
        if not m:
            raise Exception("Error detecting scheme repo: from '%s'. Expected is 'repo:<baseurl>[/<regex-wildcard>.rpm]" % (self.uri))

        self._baseurl = m.group(1) + '/'
        self.set_pattern(m.group(2))

        p = urllib.urlopen(self._baseurl + 'repodata/repomd.xml')
        r = re.compile('(.*)')
        r = re.compile('.*<location href="([^"]*primary.xml[^"]*)"/>.*')
        for line in p:
            m = r.match(line)
            if m:
                self._mainpage = self._baseurl + m.group(1)
                break
        p.close()
        if not hasattr(self, '_mainpage'):
            raise Exception("Could not find primary.xml in %s" % self._baseurl + 'repodata/repomd.xml')

    def parse_urls(self, page):
        for a in re.finditer('href=[\'"]([^\'"]*\.rpm)[\'"]', page):
            url = self._baseurl + a.group(1)
            if self.is_matching_url(url):
                yield url
    def raise_no_urls(self):
        raise Exception("Could not detect any URLs in '%s' repository" % self.uri)


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
        self.parser.add_argument('--rpm', '-r', action='append', help='Filenames of RPMs. Supports (local) files, file://, jenkins://, brew://, brewtask:// and repo: URI schemes')
        self.parser.add_argument('--nitrate-tag', '-t', action='append', help='Query nitrate for tests having this tag. Output is appended to $TESTS. Specifying more then once combines them as AND')
        self.parser.add_argument('--nitrate-all', '-a', action='store_true', help='Query all nitrate tests')
        self.parser.add_argument('--nitrate-exclude-tag', '-T', action='append', help='Query nitrate for tests not having this tag. Output is appended to $TESTS. In combination with --nitrate-tag this blacklists cases (after selecting then)')
        self.parser.add_argument('--nitrate-status', '-s', action='append', help='After selecting the tests by via --nitrate-tag, --nitrate-all, or --nitrate-exclude-tag, further whitelist by status')
        self.parser.add_argument('--nitrate-exclude-status', '-S', action='append', help='After selecting the tests by via --nitrate-tag, --nitrate-all, --nitrate-exclude-tag, further blacklist by status')
        self.parser.add_argument('--tests', '-c', action='append', help='Append argument to $TESTS')
        self.parser.add_argument('--job', '-j', help='beaker xml job file')
        self.parser.add_argument('--verbose', '-v', action='count', help='print more information')
        self.parser.add_argument('--reservesys', '-R', action='store_true', help='add task /distribution/reservesys')
        self.parser.add_argument('--disable-selinux', action='store_true', help='add kernel option selinux=0 to disable AVC checks ($SELINUX_DISABLED)')
        self.parser.add_argument('--var', '-V', action='append', help='Set template replacements (alternative to setting via environment variables')
        self.parser.add_argument('--hosttype', help='The host type. Known values are \'veth\', \'dcb\', \'infiniband\', and \'wifi\'. Anything else uses the default. This determines the $HOSTREQUIRES template')
        self.parser.add_argument('--jobtype', help='The job type. Known values are \'rhel70\'. Anything else uses the default to create a retention=scratch job. This determines the $JOBTYPE template')
        self.parser.add_argument('--profile', '-p', help='A predefined set of arguments. Known values are \'default\', \'veth\', \'wifi\', \'infiniband\', \'dcb\'.')


    def _prepare_rpms(self):
        if self.options.rpm is None:
            self.rpm = None
            return
        self.rpm = []
        for r in self.options.rpm:
            if r.startswith('http://') or r.startswith('https://'):
                ctor = UploadFileUrl
            elif r.startswith('jenkins://'):
                ctor = UploadFileJenkins
            elif r.startswith('brew://') or r.startswith('brewtask://'):
                ctor = UploadFileBrew
            elif r.startswith('repo:'):
                ctor = UploadFileRepo
            else:
                ctor = UploadFileSsh
            uf = ctor(r)
            uf.init()
            self.rpm.append((r, uf))

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
        self.subs['ARGV'] = ("\"" + "\" \"".join(sys.argv) + "\"").replace('"', '&quot;') if sys.argv else ''
        self.subs['ARGV_PROFILE'] = ("\"" + "\" \"".join(self.argv_profile) + "\"").replace('"', '&quot;') if hasattr(self, 'argv_profile') else ''

        for (k,v) in self.subs.iteritems():
            self._print_substitution(k, v)

    def _get_default(self, key_name):
        if not hasattr(self, '_default_var'):
            # Lazily set self._default_var from the command line arguments
            # the first time we need it
            self._default_var = {}
            if self.options.var is not None:
                for v0 in self.options.var:
                    v = v0.split('=', 1)
                    if len(v) != 2:
                        raise Exception("Invalid --var option %s. Should be NAME=VALUE" % (v0))
                    self._default_var[v[0]] = v[1]
        if key_name in self._default_var:
            return self._default_var[key_name]
        return os.environ.get(key_name)


    def __process_line_get_GIT_TARGETBRANCH_detect(self, key_name):
        # we default to 'master', unless there is an RPM that looks like it's from
        # rhel-7.0.
        v = self._get_default('GIT_TARGETBRANCH')
        if v is not None:
            return v
        if self.rpm is not None:
            for x in self.rpm:
                for u in x[1].url():
                    if re.match(r'^.*/NetworkManager-0.9.9.1-[1-9][0-9]*\.git20140326\.4dba720\.el7\.x86_64\.rpm$', u):
                        return 'rhel-7.0' # stable rhel-7.0 release
                    if re.match(r'^.*/NetworkManager-0.9.11.0-[0-9]+\.[a-f0-9]+\.el7.x86_64.rpm$', u):
                        return 'rhel-7.1' # upstream pre 1.0
                    if re.match(r'^.*/NetworkManager-0.9[0-9][0-9]+.0.0-[0-9]+\.[a-f0-9]+\.el7.x86_64.rpm$', u):
                        return 'rhel-7.1' # upstream 1.0-beta
                    if re.match(r'^.*/NetworkManager-0.9.10.[0-9]+-[0-9]+\.[a-f0-9]+\.el7.x86_64.rpm$', u):
                        return 'rhel-7.1' # 0.9.10
                    if re.match(r'^.*/NetworkManager-0.9.9.9[0-9]+-[0-9]+\.[a-f0-9]+\.el7.x86_64.rpm$', u):
                        return 'rhel-7.1' # 0.9.10-rc
                    if re.match(r'^.*/NetworkManager-0\.9\.11\..*\.git20141022.e28ee14.el7.x86_64.rpm$', u):
                        return 'rhel-7.1' # rhel-7.1-rc
                    if re.match(r'^.*/NetworkManager-1.0.[0-9]+-[0-9]+\.git20150121\.b4ea599c\.el7.x86_64.rpm$', u):
                        return 'rhel-7.1' # rhel-7.1-rc
                    if re.match(r'^.*/NetworkManager-1.0.[0-9]+-[0-9]+\.[a-f0-9]+\.el7.x86_64.rpm$', u):
                        return 'rhel-7' # upstream 1.0
                    if re.match(r'^.*/NetworkManager-1.0.[0-9]+-[0-9]+\.git20160622\.9c83d18d\.el7.x86_64.rpm$', u):
                        return 'rhel-7' # rhel-7.2-rc
                    if re.match(r'^.*/NetworkManager-1.0.[0-9]+-[0-9]+\.git20160624\.f245b49a\.el7.x86_64.rpm$', u):
                        return 'rhel-7' # rhel-7.2-rc
                    if re.match(r'^.*/NetworkManager-1.1.[0-9]+-[0-9]+\.[a-f0-9]+\.el7.x86_64.rpm$', u):
                        return 'master' # upstream 1.1
        raise Exception("could not detect the target branch. Try setting as environment variable GIT_TARGETBRANCH%s" % (
                    ((" (or try setting "+key_name+")") if key_name == 'GIT_TARGETBRANCH' else '')))

    def _detect_hosttype(self):
        return 'default'

    def _process_line_get_JOBTYPE(self, key, replacement, index=None, none=None):
        v = self._get_default('JOBTYPE')
        if v is not None:
            return v;
        jobtype = self.options.jobtype
        if jobtype == 'rhel70':
            return 'product="cpe:/o:redhat:enterprise_linux:7.0" retention_tag="active+1"'
        return 'retention_tag="scratch"'

    def _process_line_get_HOSTREQUIRES(self, key, replacement, index=None, none=None):
        v = self._get_default('HOSTREQUIRES')
        if v is not None:
            return v;
        hosttype = self.options.hosttype
        if hosttype == 'veth':
            return '<group op="=" value="desktop"/>'
        elif hosttype == 'dcb':
            return '<hostname op="=" value="wsfd-netdev7.lab.bos.redhat.com"/>'
        elif hosttype == 'infiniband':
            return '<hostname op="=" value="rdma-qe-11.lab.bos.redhat.com"/>'
        elif hosttype == 'wifi':
            return '''
                <group op="=" value="wireless"/>
                <hostname op="like" value="wlan-r2%.wlan.rhts.eng.bos.redhat.com"/>
                <!-- 8086:08ae (iwlwifi,iwldvm) Intel Corporation Centrino Wireless-N 100 doesn't support AP mode -->
                <device op="!=" vendor_id="8086" device_id="08ae"/>
		<!-- 8086:08b3 (iwlwifi,iwlmvm) Ooops-es: https://bugzilla.redhat.com/show_bug.cgi?id=1235694 -->
                <device op="!=" vendor_id="8086" device_id="08b3"/>
                <!-- Pick an Intel, so that we're not scheduled on some poor Realtek chip -->
                <device op="==" driver="iwlwifi"/>
            '''
        else:
            return '<group op="=" value="desktopqe-net"/>'

    def _process_line_get_GIT_TARGETBRANCH(self, key, replacement, index=None, none=None):
        return self.__process_line_get_GIT_TARGETBRANCH_detect("GIT_TARGETBRANCH")

    def _process_line_get_DISTRO_NAME(self, key, replacement, index=None, none=None):
        v = self._get_default('DISTO_NAME')
        if v is not None:
            return v
        target_branch = self.__process_line_get_GIT_TARGETBRANCH_detect("DISTRO_NAME")
        if target_branch == 'rhel-7.0':
            return 'RHEL-7.0-20140507.0'
        if target_branch == 'rhel-7.1':
            return 'RHEL-7.1-20141023.n.1'
        if target_branch == 'rhel-7':
            return 'RHEL-7.2-20150625.n.0'
        return 'RHEL-7.2-20150625.n.0'

    def _process_line_get_RESERVESYS(self, key, replacement, index=None, none=None):
        v = self._get_default('RESERVESYS')
        if v is not None:
            return v
        if not self.options.reservesys:
            return ""
        return '<reservesys duration="86400"/>'

    def _process_line_get_SELINUX_DISABLED(self, key, replacement, index=None, none=None):
        v = self._get_default('SELINUX_DISABLED')
        if v is not None:
            return v
        if self.options.disable_selinux:
            return 'selinux=0'
        return ''

    DefaultReplacements = {
            'WHITEBOARD'        : 'Test NetworkManager',
            'DISTRO_FAMILY'     : 'RedHatEnterpriseLinux7',
            'DISTRO_VARIANT'    : 'Workstation',
            'DISTRO_NAME'       : _process_line_get_DISTRO_NAME,
            'DISTRO_METHOD'     : 'nfs',
            'DISTRO_ARCH'       : 'x86_64',
            'HOSTREQUIRES'      : _process_line_get_HOSTREQUIRES,
            'JOBTYPE'           : _process_line_get_JOBTYPE,
            'TEST_URL'          : 'http://download.eng.brq.redhat.com/scratch/vbenes/NetworkManager-rhel-7.tar.gz',
            'GIT_TARGETBRANCH'  : _process_line_get_GIT_TARGETBRANCH,
            'UUID'              : str(uuid.uuid4()),
            'RESERVESYS'        : _process_line_get_RESERVESYS,
            'SELINUX_DISABLED'  : _process_line_get_SELINUX_DISABLED,
            'CONF_LOGLEVEL'     : 'DEBUG',
            'CONF_DHCP'         : 'dhclient',
            'CONF_DEBUG'        : 'RLIMIT_CORE,fatal-warnings',
            'GIT_URL'           : 'http://code.engineering.redhat.com/gerrit/desktopqe/NetworkManager',
        }
    def _process_line_get(self, key, replacement, index=None, none=None):
        if key in replacement:
            return replacement[key]
        if not key in self.subs:
            v = self._get_default(key)
            if v is None:
                if not key in CmdSubmit.DefaultReplacements:
                    replacement[key] = None
                    return none
                v = CmdSubmit.DefaultReplacements[key]
                if not isinstance(v, basestring):
                    v = v(self, key, replacement, index, none)
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
                l = l[1:]
                r = r + '$'
                continue
            name = m.group('name')
            if name == '$':
                r = r + '$'
            elif m.group('name0'):
                r = r + self._process_line_get(m.group('name0'), replacements, none='')
            elif m.group('name1'):
                r = r + self._process_line_get(m.group('name1'), replacements, index=m.group('index1'), none='')
            else:
                r = r + '$' + name
            l = m.group('rest')
            if not l:
                return r

    def run(self, argv):
        self.options = self.parser.parse_args(argv)

        if self.options.profile:
            argv_profiles = {
                'default':    [ "-s", "CONFIRMED",                             "-a", "-t", "t-master", "-T", "wifi", "-T", "infiniband", "-T", "dcb", "-T", "no-t-master" ],
                'veth':       [ "-s", "CONFIRMED", "--hosttype", "veth",       "-a", "-t", "t-master", "-T", "wifi", "-T", "infiniband", "-T", "dcb", "-T", "no-t-master" ],
                'wifi':       [ "-s", "CONFIRMED", "--hosttype", "wifi",       "-t", "wifi" ],
                'infiniband': [ "-s", "CONFIRMED", "--hosttype", "infiniband", "-t", "infiniband" ],
                'dcb':        [ "-s", "CONFIRMED", "--hosttype", "dcb",        "-t", "dcb" ],
            }
            if self.options.profile not in argv_profiles:
                raise Exception("Unknown profile \"%s\". Valid values are %s" % (self.options.profile, argv_profiles.keys()))
            self.argv_profile = argv_profiles[self.options.profile]
            self.options = self.parser.parse_args(self.argv_profile + argv)

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
            temp = tempfile.NamedTemporaryFile(prefix='bkr_job.xml.', delete=False)
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
