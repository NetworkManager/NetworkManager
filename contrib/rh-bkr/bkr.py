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


devnull = open(os.devnull, 'w')
timestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S');

def _check_output(*popenargs, **kwargs):
    if "check_output" in dir(subprocess):
        return subprocess.check_output(*popenargs, **kwargs)

    # check_output is Python 2.7, reimplement it for older version.
    # See https://hg.python.org/cpython/file/d37f963394aa/Lib/subprocess.py#l544
    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')

    process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
    output, unused_err = process.communicate()
    retcode = process.poll()
    if retcode:
        cmd = kwargs.get("args")
        if cmd is None:
            cmd = popenargs[0]
        error = subprocess.CalledProcessError(retcode, cmd)
        error.output = output
        raise error
    return output

def id_generator(size=6, chars=string.ascii_lowercase + string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))

def is_sequence(arg):
    return (not hasattr(arg, "strip") and
            hasattr(arg, "__getitem__") or
            hasattr(arg, "__iter__"))

def seq_unique(seq):
    s = set()
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

def _nitrate_base_filter(test_plan, additional=None, default=None):
    # see https://tcms.engineering.redhat.com/plan/6726/networkmanager#treeview
    # see https://tcms.engineering.redhat.com/plan/18716/networkmanager#treeview
    if default is None:
        # f = {'plan__component__name': 'NetworkManager'}
        if test_plan is None or test_plan == 'devel':
            f = {'plan__parent_id': '18716'}
        elif test_plan == 'rhel-7.1':
            f = {'plan__parent_id': '6726'}
        else:
            f = {'plan__parent_id': test_plan}
    else:
        f = dict(default);

    if additional:
        for key,value in additional.iteritems():
            f[key] = value
    return f

_nitrate_cases_searched_by_tag = {}
def nitrate_get_cases_by_tag(test_plan, tag=None, tag_name=None, tag_id=None):
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
        cases = nitrate.Nitrate()._server.TestCase.filter(_nitrate_base_filter(test_plan, {'tag' : tag_id}))
        for case in cases:
            _nitrate_add_case(case, tag_id)
        _nitrate_cases_searched_by_tag[tag_id] = 1
    return [ case for case_id, case in _nitrate_cases.iteritems() if tag_id in case['tag'] ]

_nitrate_get_cases_all = False
def nitrate_get_cases_all(test_plan):
    global _nitrate_get_cases_all
    if not _nitrate_get_cases_all:
        cases = nitrate.Nitrate()._server.TestCase.filter(_nitrate_base_filter(test_plan))
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

def nitrate_cases_get(test_plan, tags=None, no_tags=None, include_all=False):
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
        cases_tag = [ nitrate_get_cases_by_tag(test_plan, tag_name=tag) for tag in tags ]
    if include_all:
        # only blacklist of ~all~. Fetch first all.
        cases_tag.append(nitrate_get_cases_all(test_plan))
    if no_tags:
        cases_no_tag = [ nitrate_get_cases_by_tag(test_plan, tag_name=tag) for tag in no_tags ]

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

def nitrate_get_cases_by_one_tag(test_plan, tag_name):
    tag = nitrate_get_tag_by_name(tag_name, True)
    cases = nitrate_get_cases_all(test_plan)
    cases_with_tag = nitrate_get_cases_by_tag(test_plan, tag)
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
            output = _check_output(args, stderr=stderr)
    except subprocess.CalledProcessError, e:
        print "Error invoking command for %s: %s" % (reason, ' '.join(args))
        print ''.join(['++ ' + x + '\n' for x in e.output.splitlines()])
        sys.exit("invoking command failed");
    return output

def bkr_wait_completion(job_id):
    import pexpect
    print(">> bkr-wait-completion: job %s : wait for job completion..." % (job_id))
    command = "bkr job-watch J:%s" % job_id
    process = pexpect.spawn(command)
    r = process.expect(['--> Reserved', pexpect.EOF], timeout=None)
    if r == 0:
        print(">> bkr-wait-completion: job %s : completed and system is now reserved" % (job_id))
        process.terminate()
    if r == 1:
        print(">> bkr-wait-completion: job %s : completed" % (job_id))

class RpmScheme:
    def __init__(self, uri, arch):
        self.uri = uri
        self.arch = arch if arch is not None else 'x86_64'
        self.arch_re = re.escape(self.arch)
    def urls(self):
        raise NotImplementedError("not implemented")
class RpmSchemeNone(RpmScheme):
    def __init__(self, uri, arch):
        RpmScheme.__init__(self, uri, arch)
    def urls(self):
        return []
class RpmSchemeUrl(RpmScheme):
    def __init__(self, uri, arch):
        RpmScheme.__init__(self, uri, arch)
    def urls(self):
        return [self.uri]
class RpmSchemeRpm(RpmScheme):
    def __init__(self, uri, arch):
        RpmScheme.__init__(self, uri, arch)
    def urls(self):
        if not hasattr(self, '_urls'):
            u = self.uri
            if u.startswith("rpm://"):
                u = u[len("rpm://"):]
            self._urls = u.replace(',',' ').split(' ')
        return self._urls
class RpmScheme_ParseWebsite(RpmScheme):
    def __init__(self, uri, arch):
        self._pattern = None
        RpmScheme.__init__(self, uri, arch)

    @property
    def pattern(self):
        if self._pattern is not None:
            return self._pattern
        return '^.*/NetworkManager(-adsl|-bluetooth|-config-connectivity-fedora|-debuginfo|-glib|-libnm|-team|-tui|-wifi|-wwan)?-[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?-[^ /]*\.%s\.rpm$' % (self.arch_re)
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
        p = '^.*/([^/]+\.(src|noarch|%s)\.rpm)$' % (self.arch_re)
        if re.match(p, url):
            if re.search(self.pattern, url):
                return True
        return False

    def read_page(self, url = None, follow_gz = True):
        if url is None:
            url = self._mainpage
        p = urllib.urlopen(url)
        page = p.read()
        p.close()

        if follow_gz and re.match('.*\.gz$', url):
            import gzip, StringIO
            p = StringIO.StringIO(page)
            page = gzip.GzipFile(fileobj=p).read()
            p.close()
        return page

    def urls(self):
        if not hasattr(self, '_urls'):
            self.parse_uri()

            page = self.read_page()

            urls = list(self.parse_urls(page))
            if not urls:
                self.raise_no_urls()
            self._urls = urls
        return self._urls

class RpmSchemeJenkins(RpmScheme_ParseWebsite):
    jenkins_base_url = 'http://testuslav.usersys.redhat.com:8080/job/NetworkManager/'
    def __init__(self, uri, arch):
        RpmScheme_ParseWebsite.__init__(self, uri, arch)
    def parse_uri(self):
        m = re.match('^jenkins://([0-9]+)(/(.+)|/?)?$', self.uri)
        if not m:
            raise Exception("Error detecting uri scheme jenkins:// from '%s'. Expected is 'jenkins://[ID]/[regex-wildcard]" % (self.uri))
        self._id = int(m.group(1))
        self.set_pattern(m.group(3))
        self._mainpage = '%s%d/' % (RpmSchemeJenkins.jenkins_base_url, self._id)
    def parse_urls(self, page):
        for a in re.finditer('href=[\'"](artifact/[^\'"]*\.rpm)[\'"]', page):
            url = self._mainpage + a.group(1)
            if self.is_matching_url(url):
                yield url
    def raise_no_urls(self):
        raise Exception("Could not detect any URLs on jenkins for '%s' (see %s%s/)" % (self.uri, RpmSchemeJenkins.jenkins_base_url, self._id))

class RpmSchemeBrew(RpmScheme_ParseWebsite):
    brew_base_url = 'https://brewweb.engineering.redhat.com/brew/'
    def __init__(self, uri, arch):
        RpmScheme_ParseWebsite.__init__(self, uri, arch)
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
            self._mainpage = '%sbuildinfo?buildID=%s' % (RpmSchemeBrew.brew_base_url, self._id)
        elif self._type == "brewtask":
            self._mainpage = '%staskinfo?taskID=%s' % (RpmSchemeBrew.brew_base_url, self._id)

    def parse_urls(self, page):
        found_anything = False
        if self._type == "brew":
            p = 'href=[\'"](http://download.eng.bos.redhat.com/brewroot/packages/[^\'"]*\.rpm)[\'"]'
        elif self._type == "brewtask":
            p = 'href=[\'"](http://download.eng.bos.redhat.com/brewroot/work/tasks/[^\'"]*\.rpm)[\'"]'

        for a in re.finditer(p, page):
            found_anything = True
            url = a.group(1)
            if self.is_matching_url(url):
                yield url

        if not found_anything and self._type == "brewtask":
            # when the task-id is the main-page, we have to repeat... search deeper.
            p2 = '<a href="(taskinfo\?taskID=[0-9]+)" class="taskclosed" title="closed">buildArch \(.*.rpm, %s\)</a>' % (self.arch_re)
            for a in re.finditer(p2, page):
                page = self.read_page('https://brewweb.engineering.redhat.com/brew/%s' % (a.group(1)))
                for a in re.finditer(p, page):
                    url = a.group(1)
                    if self.is_matching_url(url):
                        yield url
                return
            return


    def raise_no_urls(self):
        if self.pattern_is_default:
            raise Exception("Could not detect any URLs on brew for '%s' (see \"%s\"). Try giving a pattern \"%s://%s/.*\"" % (self.uri, self._mainpage, self._type, self._id))
        raise Exception("Could not detect any URLs on brew for '%s' (see \"%s\")" % (self.uri, self._mainpage))

class RpmSchemeRepo(RpmScheme_ParseWebsite):
    def __init__(self, uri, arch):
        RpmScheme_ParseWebsite.__init__(self, uri, arch)
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
        latest = {}
        for a in re.finditer('href=[\'"]([^\'"]*?([^\'"/]+)-[^\'"-]+-[^\'"-]+\.rpm)[\'"]', page):
            url = self._baseurl + a.group(1)
            if self.is_matching_url(url):
                latest[a.group(2)] = self._baseurl + a.group(1)
        return latest.values()
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
        self.parser.add_argument('--rpm', '-r', action='append', help='Filenames of RPMs. Supports (local) files, rpm://, jenkins://, brew://, brewtask:// and repo: URI schemes')
        self.parser.add_argument('--build-id', '-b', help='Set to a git commit id or branch name of the upstream git repository of NM. If present, the script will build NM from source')
        self.parser.add_argument('--nitrate-tag', '-t', action='append', help='Query nitrate for tests having this tag. Output is appended to $TESTS. Specifying more then once combines them as AND')
        self.parser.add_argument('--nitrate-all', '-a', action='store_true', help='Query all nitrate tests')
        self.parser.add_argument('--nitrate-exclude-tag', '-T', action='append', help='Query nitrate for tests not having this tag. Output is appended to $TESTS. In combination with --nitrate-tag this blacklists cases (after selecting then)')
        self.parser.add_argument('--nitrate-status', '-s', action='append', help='After selecting the tests by via --nitrate-tag, --nitrate-all, or --nitrate-exclude-tag, further whitelist by status')
        self.parser.add_argument('--nitrate-exclude-status', '-S', action='append', help='After selecting the tests by via --nitrate-tag, --nitrate-all, --nitrate-exclude-tag, further blacklist by status')
        self.parser.add_argument('--nitrate-test-plan', '-P', help='Select the nitrate-test-plan for loading tests. Currently supported: \'devel\' (\'18716\'), \'rhel-7.1\' (\'6726\') or the numeric id of parent plan. The default depends on the target-branch. See for example https://tcms.engineering.redhat.com/plan/18716/networkmanager#treeview')
        self.parser.add_argument('--tests', '-c', action='append', help='Append argument to $TESTS')
        self.parser.add_argument('--job', '-j', help='beaker xml job file')
        self.parser.add_argument('--job-default', '-J', action='store_true', help='Use default job file. Only has effect if --job is not specified')
        self.parser.add_argument('--verbose', '-v', action='count', help='print more information')
        self.parser.add_argument('--reservesys', '-R', nargs='?', choices=['if_fail', 'new'], default=argparse.SUPPRESS, help='add task /distribution/reservesys (same as --reservesys-time=86400')
        self.parser.add_argument('--reservesys-time', help='add task /distribution/reservesys with a duration in second')
        self.parser.add_argument('--disable-selinux', action='store_true', help='add kernel option selinux=0 to disable AVC checks ($SELINUX_DISABLED)')
        self.parser.add_argument('--var', '-V', action='append', help='Set template replacements (alternative to setting via environment variables')
        self.parser.add_argument('--hosttype', help='The host type. Known values are \'veth\', \'dcb\', \'infiniband\', and \'wifi\'. Anything else uses the default. This determines the $HOSTREQUIRES template')
        self.parser.add_argument('--jobtype', help='The job type. Known values are \'rhel70\'. Anything else uses the default to create a retention=scratch job. This determines the $JOBTYPE template')
        self.parser.add_argument('--profile', '-p', help='A predefined set of arguments. Known values are \'default\', \'veth\', \'wifi\', \'infiniband\', \'dcb\'.')
        self.parser.add_argument('--bkr-write-job-id', help='If specified, write the job ID to the specified file.')
        self.parser.add_argument('--bkr-wait-completion', action='store_true', help='Whether to wait for completion of the beaker job')
        self.parser.add_argument('--bkr-job-results', help='If specified, write the job results to the specified file. Implies --bkr-wait-completion.')
        self.parser.add_argument('--valgrind', action='store_true', help='setup the valgrind wrapper')


    def _prepare_rpms(self):
        if self.options.rpm is None:
            self.rpm = None
            return
        self.rpm = []
        for r in self.options.rpm:
            if r.startswith('http://') or r.startswith('https://'):
                ctor = RpmSchemeUrl
            elif r.startswith('jenkins://'):
                ctor = RpmSchemeJenkins
            elif r.startswith('brew://') or r.startswith('brewtask://'):
                ctor = RpmSchemeBrew
            elif r.startswith('repo:'):
                ctor = RpmSchemeRepo
            elif r == 'none':
                ctor = RpmSchemeNone
            else:
                ctor = RpmSchemeRpm
            uf = ctor(r, self._get_var ("ARCH"))
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
            self.subs['RPM_LIST'] = [ u for x in self.rpm for u in x[1].urls() ]

        tests = []
        t = self._get_var("TESTS")
        if t:
            tests.extend([t])
        if self.options.tests:
            tests.extend(self.options.tests)
        if self.options.nitrate_all or self.options.nitrate_tag or self.options.nitrate_exclude_tag:

            cases, no_cases = nitrate_cases_get(self._get_nitrate_test_plan(), self.options.nitrate_tag, self.options.nitrate_exclude_tag, self.options.nitrate_all)
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
            tests.extend(sorted(set([nitrate_get_script_name_for_case(case) for case_id, case in cases.iteritems()])))
        elif self.options.nitrate_status or self.options.nitrate_exclude_status:
            raise Exception("--nitrate-status or --nitrate-exclude-status makes only sense with selecting nitrate tags")

        self.subs['TESTS'] = ','.join(tests)
        self.subs['ARGV'] = ("\"" + "\" \"".join(sys.argv) + "\"").replace('"', '&quot;') if sys.argv else ''
        self.subs['ARGV_PROFILE'] = ("\"" + "\" \"".join(self.argv_profile) + "\"").replace('"', '&quot;') if hasattr(self, 'argv_profile') else ''

        for (k,v) in self.subs.iteritems():
            self._print_substitution(k, v)

    def _get_var(self, key_name, default_fallback=True):
        if not hasattr(self, '_var'):
            # Lazily set self._var from the command line arguments
            # the first time we need it
            self._var = {}
            self._var_opts = {}
            if self.options.var is not None:
                for v0 in self.options.var:
                    v = v0.split('=', 1)
                    if len(v) != 2:
                        raise Exception("Invalid --var option %s. Should be NAME=VALUE" % (v0))
                    self._var[v[0]] = v[1]
                    self._var_opts[v[0]] = v[1]
        if not default_fallback:
            if key_name in self._var_opts:
                return self._var_opts[key_name]
        else:
            if key_name in self._var:
                return self._var[key_name]
        v = os.environ.get(key_name)
        if not default_fallback:
            return v
        if v is None and key_name in CmdSubmit.DefaultReplacements:
            v = CmdSubmit.DefaultReplacements[key_name]
            if not isinstance(v, basestring):
                self._var[key_name] = None
                v = v(self, key_name)
        self._var[key_name] = v
        return v


    def _get_nitrate_test_plan(self):
        if self.options.nitrate_test_plan:
            return self.options.nitrate_test_plan

        # if unspecified, detect the test-plan based on the target-branch.
        try:
            target_branch = self.__process_line_get_GIT_TEST_BRANCH_detect("nitrate-test-plan")
        except:
            target_branch = None

        if target_branch == 'rhel-7.0' or \
           target_branch == 'rhel-7.1':
            t = 'rhel-7.1'
        else:
            t = 'devel'
        print("Detected nitrate-test-plan=%s" % (t))
        return t

    def __process_line_get_GIT_TEST_BRANCH_detect(self, key_name):
        # we default to 'master', unless there is an RPM that looks like it's from
        # rhel-7.0.
        v = self._get_var('GIT_TEST_BRANCH')
        if v is not None:
            return v
        if self.rpm is not None:
            for x in self.rpm:
                for u in x[1].urls():
                    if re.match(r'^.*/NetworkManager-0.9.9.1-[1-9][0-9]*\.git20140326\.4dba720\.el7\.[^.]+\.rpm$', u):
                        return 'rhel-7.0' # stable rhel-7.0 release
                    if re.match(r'^.*/NetworkManager-0.9.11.0-[0-9]+\.[a-f0-9]+\.el7\.[^.]+\.rpm$', u):
                        return 'rhel-7.1' # upstream pre 1.0
                    if re.match(r'^.*/NetworkManager-0.9[0-9][0-9]+.0.0-[0-9]+\.[a-f0-9]+\.el7\.[^.]+\.rpm$', u):
                        return 'rhel-7.1' # upstream 1.0-beta
                    if re.match(r'^.*/NetworkManager-0.9.10.[0-9]+-[0-9]+\.[a-f0-9]+\.el7\.[^.]+\.rpm$', u):
                        return 'rhel-7.1' # 0.9.10
                    if re.match(r'^.*/NetworkManager-0.9.9.9[0-9]+-[0-9]+\.[a-f0-9]+\.el7\.[^.]+\.rpm$', u):
                        return 'rhel-7.1' # 0.9.10-rc
                    if re.match(r'^.*/NetworkManager-0\.9\.11\..*\.git20141022.e28ee14.el7\.[^.]+\.rpm$', u):
                        return 'rhel-7.1' # rhel-7.1-rc
                    if re.match(r'^.*/NetworkManager-1.0.[0-9]+-[0-9]+\.git20150121\.b4ea599c\.el7\.[^.]+\.rpm$', u):
                        return 'rhel-7.1' # rhel-7.1-rc
                    if re.match(r'^.*/NetworkManager-1.0.[0-9]+-[0-9]+\.[a-f0-9]+\.el7\.[^.]+\.rpm$', u):
                        return 'rhel-7' # upstream 1.0
                    if re.match(r'^.*/NetworkManager-1.0.[0-9]+-[0-9]+\.git20160622\.9c83d18d\.el7\.[^.]+\.rpm$', u):
                        return 'rhel-7' # rhel-7.2-rc
                    if re.match(r'^.*/NetworkManager-1.0.[0-9]+-[0-9]+\.git20160624\.f245b49a\.el7\.[^.]+\.rpm$', u):
                        return 'rhel-7' # rhel-7.2-rc
                    if re.match(r'^.*/NetworkManager-1.0.4-[0-9]+\.el7\.[^.]+\.rpm$', u) or \
                       re.match(r'^.*/NetworkManager-1.0.6-[0-9]+\.el7\.[^.]+\.rpm$', u):
                        return 'rhel-7' # rhel-7.2
        # Master now tests everything
        return 'master'

    def _detect_hosttype(self):
        return 'default'

    def _get_var_for_JOBTYPE(self, key):
        v = self._get_var('JOBTYPE')
        if v is not None:
            return v;
        jobtype = self.options.jobtype
        if jobtype == 'rhel70':
            return 'product="cpe:/o:redhat:enterprise_linux:7.0" retention_tag="active+1"'
        return 'retention_tag="scratch"'

    def _get_var_for_HOSTREQUIRES(self, key):
        v = self._get_var('HOSTREQUIRES')
        if v is not None:
            return v;
        hosttype = self.options.hosttype
        if hosttype == 'veth':
            return '<group op="=" value="desktop"/>'
        elif hosttype == 'dcb':
            return '<hostname op="=" value="wsfd-netdev7.lab.bos.redhat.com"/>'
        elif hosttype == 'infiniband':
            return '<group op="=" value="RDMA - ib0"/>'
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

    def _get_var_for_GIT_TEST_BRANCH(self, key):
        return self.__process_line_get_GIT_TEST_BRANCH_detect("GIT_TEST_BRANCH")

    def _get_var_for_DISTRO_NAME(self, key):
        v = self._get_var('DISTO_NAME')
        if v is not None:
            return v
        target_branch = self.__process_line_get_GIT_TEST_BRANCH_detect("DISTRO_NAME")
        if target_branch == 'rhel-7.0':
            return 'RHEL-7.0-20140507.0'
        if target_branch == 'rhel-7.1':
            return 'RHEL-7.1-20141023.n.1'
        if target_branch == 'rhel-7':
            pass
        return 'RHEL-7.2-20150907.n.0'

    def _get_var_for_DISTRO_TAG(self, key):
        v = self._get_var('DISTRO_TAG')
        if v:
            return v
        target_branch = self.__process_line_get_GIT_TEST_BRANCH_detect("DISTRO_TAG")
        if target_branch == 'rhel-7.0':
            return 'RHEL-7_0-Z-branch'
        if target_branch == 'rhel-7.1':
            return 'RHEL-7_1-Z-branch'
        if target_branch == 'rhel-7':
            pass
        return 'RTT_ACCEPTED'

    def _get_var_for_DISTROREQUIRES(self, key):
        v = self._get_var('DISTROREQUIRES')
        if v is not None:
            return v
        vf = self._get_var('DISTRO_FAMILY', False)
        vn = self._get_var('DISTRO_NAME', False)
        if vf:
            vn = None
        elif vn:
            vf = None
        if vn is not None:
            return '<distro_name op="=" value="%s"/>' % (vn)
        ret = '<distro_family op="=" value="%s"/>' % self._get_var('DISTRO_FAMILY')
        if vf is None:
            ret = ret + '<distro_tag op="=" value="%s"/>' % self._get_var('DISTRO_TAG', True)
        return ret

    def _get_var_for_RESERVESYS(self, key):
        v = self._get_var('RESERVESYS')
        if v is not None:
            return v

        duration = self._get_var('RESERVE')
        if self.options.reservesys_time:
            duration = self.options.reservesys_time

        if not hasattr (self.options, 'reservesys'):
            return ""
        elif self.options.reservesys == "new":
            if not duration:
                duration = '86400'
            return '<reservesys duration="%s"/>' % (duration)
        else:
            return '<task name="/distribution/reservesys" role="STANDALONE"><params>%s%s</params></task>' % (
                ('<param name="RESERVETIME" value="%d" />' % (duration) if duration else ''),
                ('<param name="RESERVE_IF_FAIL" value="True" />'if self.options.reservesys == "if_fail" else ''));

    def _get_var_for_ARCH(self, key):
        v = self._get_var('ARCH')
        if v:
            return v
        v = self._get_var('DISTRO_ARCH')
        if v is not None:
            return v
        return 'x86_64'

    def _get_var_for_SELINUX_DISABLED(self, key):
        v = self._get_var('SELINUX_DISABLED')
        if v is not None:
            return v
        if self.options.disable_selinux or self._get_var('SELINUX') == 'false':
            return 'selinux=0'
        return ''

    def _get_var_for_BUILD_ID(self, key):
        v = self._get_var('BUILD_ID')
        if v is not None:
            return v
        if self.options.build_id:
            return self.options.build_id
        return ''

    def _get_var_for_RPM_LIST(self, key):
        # RPM_LIST is provided by subs. If it is not,
        # we want to fail gracefully if BUILD_ID is set.
        # This avoids a warning.
        v = self._get_var_for_BUILD_ID (key)
        if v:
            return ''
        return None

    def _get_var_for_VALGRIND(self, key):
        if self._get_var('VALGRIND') is not None or self.options.valgrind:
            if self._get_var_for_SELINUX_DISABLED('SELINUX_DISABLED') == '':
                raise Exception("Valgrind wrapping won't work with SELinux enabled")
            return 'valgrind'
        return ''

    DefaultReplacements = {
            'WHITEBOARD'        : 'Test NetworkManager',
            'DISTRO_FAMILY'     : 'RedHatEnterpriseLinux7',
            'DISTRO_VARIANT'    : 'Server',
            'DISTRO_NAME'       : _get_var_for_DISTRO_NAME,
            'DISTRO_TAG'        : _get_var_for_DISTRO_TAG,
            'DISTRO_METHOD'     : 'nfs',
            'DISTRO_ARCH'       : 'x86_64',
            'ARCH'              : _get_var_for_ARCH,
            'HOSTREQUIRES'      : _get_var_for_HOSTREQUIRES,
            'JOBTYPE'           : _get_var_for_JOBTYPE,
            'DISTROREQUIRES'    : _get_var_for_DISTROREQUIRES,
            'TEST_URL'          : 'http://download.eng.brq.redhat.com/scratch/vbenes/NetworkManager-rhel-7.tar.gz',
            'GIT_TEST_REPO'     : 'http://code.engineering.redhat.com/gerrit/desktopqe/NetworkManager',
            'GIT_TEST_BRANCH'   : _get_var_for_GIT_TEST_BRANCH,
            'UUID'              : str(uuid.uuid4()),
            'RESERVESYS'        : _get_var_for_RESERVESYS,
            'SELINUX_DISABLED'  : _get_var_for_SELINUX_DISABLED,
            'BUILD_ID'          : _get_var_for_BUILD_ID,
            'BUILD_TEST'        : 'true',
            'BUILD_REPO'        : 'git://anongit.freedesktop.org/NetworkManager/NetworkManager',
            'CONF_LOGLEVEL'     : 'DEBUG',
            'CONF_DHCP'         : 'dhclient',
            'CONF_DEBUG'        : 'RLIMIT_CORE,fatal-warnings',
            'RPM_LIST'          : _get_var_for_RPM_LIST,
            'VALGRIND'          : _get_var_for_VALGRIND,
        }
    def _process_line_get(self, key, replacements):
        if key in replacements:
            v = replacements[key]
        else:
            if key in self.subs:
                v = self.subs[key];
                if is_sequence(v):
                    v = " \\\n\t".join(v)
            else:
                v = self._get_var(key)
            replacements[key] = v
        return v if v is not None else ''

    re_subs0 = re.compile('^(?P<prefix>[^$]*)(?P<rest>\$.*\n?)$')
    re_subs1 = re.compile('^\$(?P<var>\$|[a-zA-Z_]+)(?P<rest>.*\n?$)')
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
            var = m.group('var')
            if var == '$':
                r = r + '$'
            elif var:
                r = r + self._process_line_get(var, replacements)
            else:
                r = r + '$' + var
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

        if not self.options.job and self.options.job_default:
            self.options.job = os.path.dirname(os.path.abspath(__file__)) + '/job01.xml'

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
            replacements = sorted(replacements.iteritems(), key=lambda x: x[0])
            for (k,v) in [ (k,v) for (k,v) in replacements if v is not None ]:
                print("replace \'%s\' => '%s'" % (k, v))
            for k in [ k for (k,v) in replacements if v is None ]:
                print("replace \'%s\' %s" % (k, termcolor.colored("not found", 'yellow')))
            temp = tempfile.NamedTemporaryFile(prefix='bkr_job.xml.', delete=False)
            for l in job:
                temp.write(l)
            temp.close()

            print("Write job '%s' to file '%s'" % (self.options.job, temp.name));

        if self.options.job:
            args = ['bkr', 'job-submit', temp.name]
            if not self.options.no_test:
                out = _call(args, dry_run=True, verbose=True)
            else:
                out = _call(args, dry_run=False, verbose=True)
                print("Job successfully submitted: " + out)
                m = re.match('.*J:([0-9]+).*', out)
                if not m:
                    raise Exception("Failed to submit job. Command did't return a job-id")
                job_id = m.group(1)
                print("URL: https://beaker.engineering.redhat.com/jobs/%s" % (job_id))
                print("     https://beaker.engineering.redhat.com/jobs/mine");

                if self.options.bkr_write_job_id:
                    with open(self.options.bkr_write_job_id, "w") as text_file:
                        text_file.write("J:%s\n" % (job_id))

                if self.options.bkr_wait_completion or self.options.bkr_job_results:
                    bkr_wait_completion(job_id)
                if self.options.bkr_job_results:
                    print(">> bkr-job-results: job %s : retrieve job results in file %s" % (job_id, self.options.bkr_job_results))
                    with open(self.options.bkr_job_results, "w") as text_file:
                        r = subprocess.call(["bkr", "job-results", "--prettyxml", "J:%s" % (job_id)], stdout=text_file)
                        if r != 0:
                            raise Exception("getting job results failed")


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
