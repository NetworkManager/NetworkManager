#!/usr/bin/env python

import sys
import argparse
import subprocess
import os
import re
import kobo.xmlrpc
import xmlrpclib
import termcolor


devnull = open(os.devnull, 'w')

def _call(args):
    try:
        output = subprocess.check_output(args, stderr=devnull)
    except subprocess.CalledProcessError:
        print("Error invoking command: %s" % (' '.join(args)))
        sys.exit(1)
    return output

def _read_config_file(filename):
    values = {}
    with open(filename) as f:
        for line in f:
            line = line.strip()
            if not line or line[0] == '#':
                continue
            name, var = line.partition("=")[::2]
            var = var.strip()
            if var and ((var[0]=='"' and var[-1]=='"') or (var[0]=="'" and var[-1]=="'")):
               var = var[1:-1]
            values[name.strip()] = var
    return values

def git_ref_list(commit):
    return _call(['git', 'rev-list', '--no-walk', commit]).splitlines()

_git_commit_message = {}
def git_commit_message(shaid):
    if not _git_commit_message.has_key(shaid):
        _git_commit_message[shaid] = _call(['git', 'log', '--format=%B', '-n', '1', shaid])
    return _git_commit_message[shaid]

_git_summary = {}
def git_summary(commit, color=False):
    tag = (commit,color)
    if not _git_summary.has_key(tag):
        if color:
            pretty = '--pretty=format:%Cred%h%Creset - %Cgreen(%ci)%Creset [%C(yellow)%an%Creset] %s%C(yellow)%d%Creset'
        else:
            pretty = '--pretty=format:%h - (%ci) [%an] %s%d'
        _git_summary[tag] = _call(['git', 'log', '-n1', pretty, '--abbrev-commit', '--date=local', commit])
    return _git_summary[tag]

_git_get_commit_date = {}
def git_get_commit_date(shaid):
    if not _git_get_commit_date.has_key(shaid):
        _git_get_commit_date[shaid] = int(_call(['git', 'log', '--format=%ct', '-n', '1', shaid]))
    return _git_get_commit_date[shaid]


class PasswordError(ValueError):
    pass


class CmdBase:
    def __init__(self, name):
        self.name = name
        self.parser = None

    def run(self, argv):
        print_usage()


class BzClient:
    COMMON_FIELDS = ['id', 'depends_on', 'blocks', 'flags', 'keywords', 'status', 'component']

    def __init__(self, url, config):
        transport = None
        use_https = False
        if url.startswith('https://'):
            transport = kobo.xmlrpc.SafeCookieTransport()
            use_https = True
        else:
            transport = kobo.xmlrpc.CookieTransport()
        self._key_part = (url, use_https)
        self._client = xmlrpclib.ServerProxy(url, transport=transport)
        self._config = config

    def _login(self, user, password):
        self._client.User.login({'login': user,
                                'password': password})

    _getBZDataCache = {}
    def getBZData(self, bzid, include_fields = COMMON_FIELDS):
        if not self._config.get('rhbz_passwd', None) or not self._config.get('rhbz_user', None):
            raise PasswordError('The Bugzilla password has not been set')
        user = self._config['rhbz_user'];
        passwd = self._config['rhbz_passwd']

        key = sorted(include_fields)
        key.append(self._key_part)
        key.append(user)
        key.append(passwd)
        key.append(bzid)
        key = tuple(key)

        if BzClient._getBZDataCache.has_key(key):
            return BzClient._getBZDataCache[key]

        self._login(user, passwd)

        bugs_data = self._client.Bug.get({'ids': bzid,
                                          'include_fields': include_fields})
        bug_data = bugs_data['bugs'][0]
        BzClient._getBZDataCache[key] = bug_data
        return bug_data



# class to hold information about a bugzilla entry
class BzInfo:
    def __init__(self, bzid):
        self.bzid = bzid
    @property
    def bztype(self):
        return None
    @property
    def url(self):
        return None
    def __cmp__(self, other):
        return cmp( (self.bztype, self.bzid), (other.bztype, other.bzid) )
    def __hash__(self):
        return hash( (self.bztype, self.bzid) )
    def __str__(self):
        return "%s #%s" % (self.bztype, self.bzid)
    def __repr__(self):
        return "(\"%s\", \"%s\")" % (self.bztype, self.bzid)

    def getBZData(self, field=None):
        if not hasattr(self, '_bzdata'):
            self._bzdata = self._fetchBZData()
        if self._bzdata is None:
            self._bzdata = {}
        if field is None:
            return self._bzdata
        return self._bzdata.get(field, None)
    def _fetchBZData(self):
        return None



class BzInfoBgo(BzInfo):
    def __init__(self, bzid):
        BzInfo.__init__(self, bzid)
    @BzInfo.bztype.getter
    def bztype(self):
        return "bgo"
    @BzInfo.url.getter
    def url(self):
        return "https://bugzilla.gnome.org/show_bug.cgi?id=%s" % self.bzid


class BzInfoRhbz(BzInfo):
    def __init__(self, bzid):
        BzInfo.__init__(self, bzid)
    @BzInfo.bztype.getter
    def bztype(self):
        return "rhbz"
    @BzInfo.url.getter
    def url(self):
        return "https://bugzilla.redhat.com/show_bug.cgi?id=%s" % self.bzid

    def _fetchBZData(self):
        return BzClient('https://bugzilla.redhat.com/xmlrpc.cgi', config).getBZData(self.bzid)



class UtilParseCommitMessage(CmdBase):

    _patterns = [
            ('(^|\W)(?P<type>bgo)[ ]?[#]?(?P<id>[0-9]{4,7})($|\W)',                     lambda m: BzInfoBgo(m.group('id'))),
            ('https://bugzilla\.gnome\.org/show_bug\.cgi\?id=(?P<id>[0-9]{4,7})($|\W)', lambda m: BzInfoBgo(m.group('id'))),
            ('(^|\W)(?P<type>rh(bz)?)[ ]?[#]?(?P<id>[0-9]{4,7})($|\W)',                 lambda m: BzInfoRhbz(m.group('id'))),
            ('https://bugzilla\.redhat\.com/show_bug.cgi\?id=(?P<id>[0-9]{4,7})($|\W)', lambda m: BzInfoRhbz(m.group('id'))),
            ('(^|\W)#(?P<id>[0-9]{4,7})($|\W)',                                         lambda m: BzInfoRhbz(m.group('id'))),
            ('(^|\W)(bz|bug)[ ]?[#]?(?P<id>[0-9]{4,7})($|\W)',                          lambda m: BzInfoRhbz(m.group('id'))),
        ]
    _patterns = [(re.compile(p[0]), p[1]) for p in _patterns]

    def __init__(self, commit, result=None, git_backend=True, commit_date=0):
        self.commit = commit
        self._result = result
        self._git_backend = git_backend
        self._commit_date = commit_date

    @property
    def result(self):
        if not self._result and self._git_backend:
            message = git_commit_message(self.commit)
            data = []

            for pattern in UtilParseCommitMessage._patterns:
                for match in pattern[0].finditer(message):
                    m = pattern[1](match)
                    if m:
                        data.append(m)

            self._result = list(set(data))
        return self._result

    def __cmp__(self, other):
        if self._git_backend != other._git_backend:
            return cmp(self._git_backend, other._git_backend)
        return cmp(self.commit, other.commit)
    def __hash__(self):
        return hash(self.commit)
    def __str__(self):
        return str( (self.commit, self.result) )
    def __repr__(self):
        return str(self)

    def commit_summary(self, color):
        if self._git_backend:
            return git_summary(self.commit, color)
        return self.commit
    def get_commit_date(self):
        if self._git_backend:
            return git_get_commit_date(self.commit)
        return self._commit_date





class CmdParseCommitMessage(CmdBase):

    def __init__(self, name):
        CmdBase.__init__(self, name)

        self.parser = argparse.ArgumentParser(prog=sys.argv[0] + " " + name, description='Parse commit messages.')
        self.parser.add_argument('--color', '-c', dest='color', action='store_true')
        self.parser.add_argument('--conf', metavar='conf', default=('%s/.bzutil.conf' % os.path.expanduser("~")))
        self.parser.add_argument('--bz', action='append')
        self.parser.add_argument('commit', metavar='commit', type=str, nargs='+',
                                 help='commit ids to parse')

    @staticmethod
    def _order_keys(keys, ordered):
        return [o for o in ordered if o in keys]

    _colormap_flag = {
            '+': 'green',
            '?': 'yellow',
        }
    _colormap_status = {
            'POST': 'green',
            'MODIFIED': 'yellow',
            'CLOSED': 'green',
        }


    def _colored(self, value, colormapping, defaultcolor='red'):
        v = '>> ' + value
        if not self.options.color:
            return v
        color = colormapping.get(value, defaultcolor)
        return termcolor.colored(v, color)

    def run(self, argv):
        self.options = self.parser.parse_args(argv)

        global config
        if not os.path.exists(self.options.conf):
            self.parser.error('config file does not exist: %s' % self.options.conf)
        config = _read_config_file(self.options.conf)

        result_man = []
        obzi = 0
        for obz in self.options.bz:
            bz_tuples = [bz for bz in re.split('[,; ]', obz) if bz]
            result_man2 = []
            for bzii in bz_tuples:
                bzi = bzii.partition(':')[::2]
                if not bzi[0] or not bzi[1] or not re.match('^[0-9]{4,7}$', bzi[1]):
                    raise self.parser.error('Invalid bugzilla option --bz \"%s\" (%s)' % (obz, bzii))
                if bzi[0] == 'rhbz' or bzi[0] == 'rh':
                    result_man2.append(BzInfoRhbz(bzi[1]))
                elif bzi[0] == 'bgo' or bzi[0] == 'bg':
                    result_man2.append(BzInfoBgo(bzi[1]))
                else:
                    raise self.parser.error('Invalid bugzilla option --bz \"%s\"' % obz)
            if not result_man2:
                raise self.parser.error('Invalid bugzilla option --bz \"%s\"' % obz)
            result_man.append(UtilParseCommitMessage('bz \"%s\"' % obz, result_man2, git_backend=False, commit_date=-obzi))
            obzi = obzi + 1

        result_all = [ (ref, [UtilParseCommitMessage(commit) for commit in git_ref_list(ref)]) for ref in self.options.commit]

        for ref_data in result_all:
            print("ref: %s" % ref_data[0])
            for commit_data in ref_data[1]:
                print("  %s" % commit_data.commit_summary(self.options.color))
                for result in commit_data.result:
                    print("    %-4s #%-8s %s" % (result.bztype, result.bzid, result.url))


        result_reduced = [ commit_data for ref_data in result_all for commit_data in ref_data[1] if commit_data.result ]
        result_reduced = result_reduced + result_man
        result_reduced = sorted(set(result_reduced), key=lambda commit_data: commit_data.get_commit_date(), reverse=True)

        print
        print('sorted:')
        for commit_data in result_reduced:
            print("  %s" % commit_data.commit_summary(self.options.color))
            for result in commit_data.result:
                print("    %-4s #%-8s %s" % (result.bztype, result.bzid, result.url))
                bzdata = result.getBZData()
                for k in CmdParseCommitMessage._order_keys(bzdata.keys(), ['status', 'flags']):
                    if k == 'flags':
                        for flag in bzdata[k]:
                            print("         %-20s = %s" % ('#'+flag['name'], self._colored(flag['status'], CmdParseCommitMessage._colormap_flag)))
                    elif k == 'status':
                        print("         %-20s = %s" % (k, self._colored(bzdata[k], CmdParseCommitMessage._colormap_status)))
            print



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


commands = {}
def commands_add(name, t, realname=None):
    commands[name] = t(realname if realname else name)


commands_add('parse',       CmdParseCommitMessage)
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
