#!/usr/bin/env python

import sys
import argparse
import subprocess
import os
import re


devnull = open(os.devnull, 'w')

def _call(args):
    try:
        output = subprocess.check_output(args, stderr=devnull)
    except subprocess.CalledProcessError:
        print("Error invoking command: %s" % (' '.join(args)))
        sys.exit(1)
    return output

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



class CmdBase:
    def __init__(self, name):
        self.name = name
        self.parser = None

    def run(self, argv):
        print_usage()


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
        return "BzInfo(\"%s\", \"%s\")" % (self.bztype, self.bzid)

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

    def __init__(self, commit):
        self.commit = commit
        self._result = None

    @property
    def result(self):
        if not self._result:
            message = git_commit_message(self.commit)
            data = []

            for pattern in UtilParseCommitMessage._patterns:
                for match in pattern[0].finditer(message):
                    m = pattern[1](match)
                    if m:
                        data.append(m)

            self._result = list(set(data))
        return self._result

    def __str__(self):
        return str( (self.commit, self.result) )
    def __repr__(self):
        return str(self)




class CmdParseCommitMessage(CmdBase):

    def __init__(self, name):
        CmdBase.__init__(self, name)

        self.parser = argparse.ArgumentParser(prog=sys.argv[0] + " " + name, description='Parse commit messages.')
        self.parser.add_argument('--color', '-c', dest='color', action='store_true')
        self.parser.add_argument('commit', metavar='commit', type=str, nargs='+',
                                 help='commit ids to parse')

    def run(self, argv):
        self.options = self.parser.parse_args(argv)

        result_all = [ (ref, [UtilParseCommitMessage(commit) for commit in git_ref_list(ref)]) for ref in self.options.commit]

        for ref_data in result_all:
            print("ref: %s" % ref_data[0])
            for commit_data in ref_data[1]:
                print("  %s" % git_summary(commit_data.commit, self.options.color))
                for result in commit_data.result:
                    print("    %-4s #%-8s %s" % (result.bztype, result.bzid, result.url))

        result_reduced = [ commit_data for ref_data in result_all for commit_data in ref_data[1] if commit_data.result ]

        print
        print('sorted:')
        for commit_data in sorted(set(result_reduced), key=lambda commit_data: git_get_commit_date(commit_data.commit), reverse=True):
            print("  %s" % git_summary(commit_data.commit, self.options.color))
            for result in commit_data.result:
                print("    %-4s #%-8s %s" % (result.bztype, result.bzid, result.url))
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
