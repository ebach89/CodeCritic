#!/usr/bin/env python3

import argparse
import gerra.endpoints.changes as ch
import os
import sys
import utilpy.cfg.yamlmisc as yamlm

from collections import defaultdict
from IPython import embed
from plumbum import local, ProcessExecutionError
from pygerrit2 import GerritRestAPI, HTTPBasicAuth
from urllib.parse import urlparse
from requests.packages import urllib3

GERRIT_SERVER_URL = ""
SCRIPT_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))
CUR_DIR = os.getcwd()

GERRIT_URL_BASE = None
# Make shell utils ready
git = local["git"]
bash = local["bash"]


def get_relation_chain(ch_api, change_info):
    """
    Determine commits in URL. Usually, URL is a one commit or a tip of
    branch ("Relation Chain") from review. Function counts only them
    (not taking into account all patches in topic)

    change_info: Dict of ChangeInfo
    output: List of Dicts, listing all commits, concerning URL passed
            (i.e single one or several ones from branch).
    """

    # To find commit in particular repo and particular branch, we need to
    # construct repo:<remote>/<branch> query for gerrit.
    out = git("remote", "-v").split('\n')[0].split('\t')
    # <remote>	<gerrit ssh url with port>/<repo> (fetch)
    # <remote>	<gerrit ssh url with port>/<repo> (push)
    remote_url = out[1].split(' ')[0]
    parsed_url = urlparse(remote_url)
    remote_path = parsed_url.path
    if remote_path[0] != '/':
        print("Path (as part of URL) on remote server does not start with '/'")
        print("Analyze printout of 'git remote -v':\n{}". format(git("remote", "-v")))
        raise
    repo = remote_path[1:]
    topic = change_info['topic']

    if repo != change_info['project']:
        # they must match.
        print("Local git info does not match info from Gerrit")
        print(f"Local git info:\n{repo}")
        print(f"Info from Gerrit:\n{change_info['project']}")
        raise

    commits_reply = ch_api.query(f"topic:{topic} status:open repo:{repo}")

    # Place all needed info about commits into special List
    commits = []
    for commit in commits_reply:
        commits.append(
            {
                "url": GERRIT_URL_BASE + "+/" + str(commit['_number']),
                'change_id': commit['change_id'],
                'subject': commit['subject'],
                '_number': commit['_number'],
                'project': commit['project'],
                'branch': commit['branch'],
                'topic': commit['topic']
            }
        )

    return commits

def handle_url(args, ch_api):
    change_info = ch_api.get_change_info(args.url)

    numeric_id = change_info["_number"]
    current_revision = change_info["current_revision"]
    fetch_info = change_info["revisions"][current_revision]["fetch"]["ssh"]

    fetch = (
        "git fetch {} {} && "
        "git checkout -b change-{} FETCH_HEAD".
        format(fetch_info["url"], fetch_info["ref"], numeric_id)
    )
    try:
        bash("-c", fetch)
    except ProcessExecutionError as ex:
        print(ex)
        sys.exit(1)

    chain = get_relation_chain(ch_api, change_info)
    chain_nr = len(chain)
    commits = []

    git_commits = git("log", "--format=%H %d %s", "-n",
                      str(chain_nr)).strip().split('\n')

    for git_commit in reversed(git_commits):
        for commit in chain:
            if commit['subject'] not in git_commit:
                continue

            git_hash = git_commit.split(' ')[0]
            files = git('show', '--pretty=', '--name-only',
                        git_hash).strip().split('\n')

            # To submit draft reviw we need revision_id. Extract it.
            change_info = ch_api.get_change_info(commit['url'])

            commits.append(
                {
                    'git_hash': git_hash,
                    'files': files,
                    'revision_id': change_info['current_revision'],
                    **commit
                }
            )
    # [{'git_hash': 'a8ff865c6c',
    #  'files': ['drivers/mtd/nand/spi/core.c',
    #   'include/linux/mtd/spinand.h'],
    #  'url': 'http://some/gerrit/url/linux-next/+/27791',
    #  'change_id': 'I487a015d8f4a7bf37e98945d7fad56d4ce440888',
    #  'subject': '1st (oldest) commit in branch',
    #  '_number': 27791,
    #  'project': 'linux/linux-next',
    #  'branch': 'feature_branch',
    #  'topic': 'upstream-feature'},
    # {'git_hash': '7196704c34',
    #  'files': ['drivers/mtd/nand/spi/Makefile',
    #   'drivers/mtd/nand/spi/core.c',
    #   'include/linux/mtd/spinand.h'],
    #  'url': 'http://some/gerrit/url/linux-next/+/24836',
    #  'change_id': 'I8917bdb3eae7e528f414589da12b629371a29444',
    #  'subject': '2nd commit in branch',
    #  '_number': 24836,
    #  'project': 'linux/linux-next',
    #  'branch': 'feature_branch',
    #  'topic': 'upstream-feature'},
    # {'git_hash': '6cd78207e5',
    #  'files': ['arch/arm/configs/versatile_defconfig'],
    #  'url': 'http://some/gerrit/url/linux-next/+/25489',
    #  'change_id': 'I7b72e09edc63960f6b8e2239d68d0d24a927491e',
    #  'subject': '3rd (newest) commit in branch',
    #  '_number': 25489,
    #  'project': 'linux/linux-next',
    #  'branch': 'feature_branch',
    #  'topic': 'upstream-feature'}]

    # The oldest commit is the first item in the list
    return commits


def filter_files(files, extensions):
    """
    Filter files by extensions

    files: list of files
    extensions: tuple of possible extensions or tuple([]), denoting all files
    """
    result = []

    if not extensions:
        # extensions == [] means all files, hence hack endswith() by empty ext
        extensions = ""

    for afile in files:
        if afile.endswith(extensions) and os.path.exists(afile):
            result.append(afile)
    return result

def handle_commit(args):
    pass

def handle_file(args):
    pass

def handle_flist(args):
    pass

def is_report_in_commit(afile, lineno, git_hash):
    """
    Returns True if paticular line (with lineno) in specified file 'afile'
    is changed by current 'commit'
    """
    if lineno == 0:
        return False

    # we need usual pager
    aline = git("--no-pager", "blame", "-l", f"-L{lineno},{lineno}", afile)
    return aline.split(" ")[0] == git_hash


def parse_cppcheck_output(report, commit, out, err):
    for line in err.strip().split("\n"):
        if len(line.strip()) == 0:
            continue

        # Filter out such rare case:
        # line:include/linux/compiler-gcc.h###0###information###This file is \
        #       not analyzed. Cppcheck failed to extract a valid \
        #       configuration. Use -v for more details.
        if "Cppcheck failed to extract a valid configuration" in line:
            continue

        afile, lineno, severity, err_msg = line.split("###")
        # Such cases is possible:
        # ######information###Cppcheck cannot find all the include files
        # 'nofile###0###information###Cppcheck cannot find all the include files (use --check-config for details)'
        if afile == "" or afile == "nofile" or lineno == "":
            continue

        # Check git blame and insert only valid reports' lines for lines,
        # touched by commit on review
        if not is_report_in_commit(afile, lineno, commit['git_hash']):
            continue

        # Form proper data structure:
        # https://gerrit-documentation.storage.googleapis.com/Documentation/3.3.0/rest-api-changes.html#comment-input
        report['comments'][afile].append({
            'path': afile,
            'line': lineno,
            'message': f"[{severity}] {err_msg}"
        })


def parse_flake8_output(report, commit, out, err):
    for line in out.strip().split("\n"):
        if len(line.strip()) == 0:
            continue

        afile, lineno, severity, err_msg = line.split("###")
        # Such cases is possible:
        # ######information###Cppcheck cannot find all the include files
        if afile == "" or lineno == "":
            continue

        # Check git blame and insert only valid reports' lines for lines,
        # touched by commit on review
        if not is_report_in_commit(afile, lineno, commit['git_hash']):
            continue

        # Form proper data structure:
        # https://gerrit-documentation.storage.googleapis.com/Documentation/3.3.0/rest-api-changes.html#comment-input
        report['comments'][afile].append({
            'path': afile,
            'line': lineno,
            'message': f"[{severity}] {err_msg}"
        })


def parse_kernel_doc_output(report, commit, out, err):
    # convert the list of lines into an iterator (lines) for further usage
    # of next()
    lines = iter(err.strip().split("\n"))
    for line in lines:
        if len(line.strip()) == 0:
            continue

        # Filter-out lines concerning deleted files:
        #   'Error: Cannot open file deleted/file/displayed/in/git/name.h'
        if not ("warning:" in line or "error:" in line):
            continue

        afile, lineno, severity, err_msg = line.split(":", maxsplit=3)

        # filter-out such non-informative lines in report:
        #   common/log.c:198: info: Scanning doc for log_dispatch
        if "info" in severity:
            continue

        # Multi-line Handling:
        # after parsing the initial line, we peek at subsequent lines.
        # * if the next line starts with whitespace (indicating
        #   continuation), it's appended to the current message.
        # * If not, it's put back into the iterator for the next iteration.
        additional_lines = []
        while True:
            try:
                next_line = next(lines)
                if next_line.startswith(" "):
                    additional_lines.append(next_line)
                else:
                    # Next line is a new warning - reconstruct the iterator
                    lines = (aline for aline in [next_line] + list(lines))
                    break
            except StopIteration:
                break  # End of lines

        # Combine additional lines if any
        if additional_lines:
            err_msg += "\n" + "\n".join(additional_lines)

        # Check git blame and insert only valid reports' lines for lines,
        # touched by commit on review
        if not is_report_in_commit(afile, lineno, commit['git_hash']):
            continue


        # Form proper data structure:
        # https://gerrit-documentation.storage.googleapis.com/Documentation/3.3.0/rest-api-changes.html#comment-input
        report['comments'][afile].append({
            'path': afile,
            'line': lineno,
            'message': f"```\n[{severity}]: {err_msg}\n```"
        })


def parse_codespell_output(report, commit, out, err):
    for line in out.strip().split("\n"):
        if len(line.strip()) == 0:
            continue

        afile, lineno, err_msg = line.split(":")
        # Commented code is from cppcheck:
        #if afile == "" or lineno == "":
        #    continue

        # Check git blame and insert only valid reports' lines for lines,
        # touched by commit on review
        if not is_report_in_commit(afile, lineno, commit['git_hash']):
            continue

        # Form proper data structure:
        # https://gerrit-documentation.storage.googleapis.com/Documentation/3.3.0/rest-api-changes.html#comment-input
        report['comments'][afile].append({
            'path': afile,
            'line': lineno,
            'message': f"misspell: {err_msg}"
        })


def parse_shellcheck_output(report, commit, out, err):
    # Filter-out the section 'For more information:' at the end of the report
    out = out.strip().split("For more information:")[0]
    # The lines 'In script.sh line 1:' are delimited by "\n\n\n"
    for line in out.strip().split("\n\n\n"):
        if len(line.strip()) == 0:
            continue

        # "In script.sh line 1:\n"
        # "blabla \n -- SC2148 (error): Add a shebang."
        afile_lineno, err_msg = line.split(":\n", maxsplit=1)
        # ['In', 'script.sh', 'line', '1']
        afile = afile_lineno.split()[1]
        lineno = afile_lineno.split()[3]
        # Such cases is possible:
        # ######information###Cppcheck cannot find all the include files
        if afile == "" or lineno == "":
            continue

        # Check git blame and insert only valid reports' lines for lines,
        # touched by commit on review
        if not is_report_in_commit(afile, lineno, commit['git_hash']):
            continue

        # Form proper data structure:
        # https://gerrit-documentation.storage.googleapis.com/Documentation/3.3.0/rest-api-changes.html#comment-input
        report['comments'][afile].append({
            'path': afile,
            'line': lineno,
            'message': f"```\n{err_msg}\n```"
        })


def tool_is_stop_execution(analyzer_config, commit, ret, out, err):
    """
    Function returns conclusion 'whether to stop command execution (due to
    command failure, no errors found) or not'?
    """
    def tool_failure_log(progname, commit, ret, out, err):
        print(f"Review: {commit['url']}")
        print(f"\tSubject: {commit['subject']}")
        print(f"\t\t[{progname}] failed with err:{ret}")
        print(f"stderr:\n\t{err}")
        print(f"stdout:\n\t{out}")

    def tool_has_no_problems_log(progname, commit):
            print(f"Review: {commit['url']}")
            print(f"\tSubject: {commit['subject']}")
            print(f"\t\t[{progname}] has NO problems.")

    progname = analyzer_config['progname']

    # Handle 'ret'
    if ret != 0:
        if progname in ['cppcheck', 'kernel-doc', 'flake8']:
            tool_failure_log(progname, commit, ret, out, err)
            return True

        elif progname in ['codespell']:
            # In case of error 65 is returned:
            #   https://github.com/codespell-project/codespell/blob/246fbf9b172c14256c68f22a98e35fde7d9c8692/codespell_lib/_codespell.py#L1349
            # In case of success 0 is returned.
            if ret != 65:
                tool_failure_log(progname, commit, ret, out, err)
                return True

        elif progname in ['shellcheck']:
            # 0 - no bugs found
            # 1 - bugs in script found
            # Catch possible rare caces
            if ret != 1:
                tool_failure_log(progname, commit, ret, out, err)
                return True

    # Handle out/err
    if progname in ['cppcheck', 'kernel-doc']:
        if len(err) == 0:
            tool_has_no_problems_log(progname, commit)
            # From the analyzer's point of view the absence of errors in code
            # is the reason for stop further command processing
            return True

        return False

    elif progname in ['flake8', 'codespell', 'shellcheck']:
        if len(out) == 0:
            tool_has_no_problems_log(progname, commit)
            return True

    return False


# fullpath: app (that is in PATH) or app's fullpath - see analyzers.yaml
# progname: analyzer name to be disbplayed in logs, e.g. cppcheck_c &
# 			cppcheck_cxx will be displayed as cppcheck in logs
#
# TODO: migrate this json to analyzers.yaml
analyzer_configs = {
    'cppcheck_c': {
        'progname': 'cppcheck',
        'command': 'cppcheck',
        'command_args': [
            '--quiet', '--enable=all', '--inconclusive', '-f', '--language=c',
            '--template={file}###{line}###{severity}###{message}'
        ],
        'file_extensions': ['.h', '.c'],
        'fullpath': '/home/19262532/Work/sources/analyzers/cppcheck/build/bin/cppcheck',
        'output_parser': parse_cppcheck_output

    },
    'cppcheck_cxx': {
        'progname': 'cppcheck',
        'command': 'cppcheck',
        'command_args': [
            '--quiet', '--enable=all', '--inconclusive', '-f', '--language=c++',
            '--template={file}###{line}###{severity}###{message}'
        ],
        'file_extensions': ['.hpp', '.cc', '.cpp'],
        'fullpath': '/home/19262532/Work/sources/analyzers/cppcheck/build/bin/cppcheck',
        'output_parser': parse_cppcheck_output
    },
    'flake8': {
        'progname': 'flake8',
        'command': 'flake8',
        'command_args': [
            '--exit-zero',
            '--format=%(path)s###%(row)d###%(code)s###%(text)s'
        ],
        'file_extensions': ['.py'],
        'fullpath': 'FLAKE8',
        'output_parser': parse_flake8_output

    },
    'kernel_doc': {
        'progname': 'kernel-doc',
        'command': './scripts/kernel-doc',
        'command_args': [
            '-v', '-none'
        ],
        'file_extensions': ['.c', '.h'],
        'fullpath': 'KERNEL_DOC',
        'output_parser': parse_kernel_doc_output
    },
    'codespell': {
        'progname': 'codespell',
        'command': 'codespell',
        'command_args': ['--skip "obj,.git,tags"'],
        'file_extensions': [],  # All files
        'fullpath': 'CODESPELL',
        'output_parser': parse_codespell_output
    },
    'shellcheck': {
        'progname': 'shellcheck',
        'command': 'shellcheck',
        'command_args': [
            '--color=never',
            '--exclude=SC1091'
        ],
        'file_extensions': ['.sh'],
        'fullpath': 'SHELLCHECK',
        'output_parser': parse_shellcheck_output
    }
}


def run_analyzer(commits, analyzer_config):
    """
    Generic function to run any code analyzer on 'commits' with help of
	'analyzer_config'

    Args:
        commits: List of commit dictionaries to analyze
        analyzer_config: Dictionary containing analyzer-specific configuration

    Returns:
        Updated commits with analysis
    """
    progname = analyzer_config['progname']
    files_filter = tuple(analyzer_config['file_extensions'])
    parse_tool_output = analyzer_config['output_parser']

    print(f"Run {progname} analysis...")

    tool_path = analyzer_config['command']
    if analyzer_config['fullpath'] and os.path.exists(analyzer_config['fullpath']):
        # use pre-installed tool in specific your system location
        tool_path = analyzer_config['fullpath']

    tool = local[tool_path][analyzer_config['command_args']]

    for commit in commits:
        commit['report'] = {}

        print(f"\n=== Analyze: {commit['subject']}")
        git("checkout", commit['git_hash'])

        ret, out, err = tool.run(
                filter_files(commit['files'], files_filter),
                retcode=None
        )

        if tool_is_stop_execution(analyzer_config, commit, ret, out, err):
            continue

        report = {}
        # "message" is printed not in-file (i.e. as Reply to whole patch)
        # Uncomment line below, when you will be ready to reveal yourself
        # as person, using Gerra & CodeCritic
        #report["message"] = f"[{progname}] Some issues need to be fixed."
        report["message"] = "I've found some issues"
        report["comments"] = defaultdict(list)

        parse_tool_output(report, commit, out, err)
        commit['report'].update(report)


def analyze(args, ch_api, commits):

    analyzers = []
    if "all" in args.analyzer and len(args.analyzer) > 1:
        args.analyzer.remove("all")
        analyzers.extend(args.analyzer)
    elif "all" in args.analyzer and len(args.analyzer) == 1:
        analyzers.extend(ANALYZERS_MAP.keys())

    for a in analyzers:
        run_analyzer(commits, analyzer_configs[a])

        if args.local:
            for commit in commits:
                if not commit['report']:
                    continue
                print("Review: {}".format(commit['url']))
                print("\tSubject: {}".format(commit['subject']))
                print(commit['report'])
                print("\n")
                continue
            return

        # Send report to Gerrit: commit-by-commit & file-by-file
        print("\n")
        for commit in commits:
            if not commit['report']:
                # Some comits can have no report at all
                continue

            for afile in commit['report']['comments']:
                # https://gerrit-documentation.storage.googleapis.com/Documentation/3.3.0/rest-api-changes.html#comment-input
                print(f"Send comments to Gerrit for {afile}:")
                print("\t\t{}".format(commit['subject']))
                print("\t\t{}".format(commit['url']))

                CommentInput_list = commit['report']['comments'][afile]
                ch_api.put_draft(commit['change_id'], commit['revision_id'],
                                 CommentInput_list)

def parse_args():
    global GERRIT_SERVER_URL

    conf = yamlm.load_config(f"{SCRIPT_DIR}/gerrit_settings.yaml")
    GERRIT_USER = conf["GERRIT_USER"]
    GERRIT_SERVER_URL = conf["GERRIT_URL"]
    GERRIT_HTTP_CRED_PWD = conf["GERRIT_HTTP_CRED_PWD"]

    ap = argparse.ArgumentParser(
        description=("Analyze gerrit-URL, git commit, ?files? and report "
                     "criticism on gerrit or locally.")
    )

    # Mutually exclusive group
    xgroup = ap.add_mutually_exclusive_group(required=True)
    xgroup.add_argument("--url", type=str,
        help=("Gerrit review URL. URL is applied to repo, from which the "
              "script is launched. URL can point to single commit or tip of "
              "branch from gerrit. Applied review looks like if you click "
              "'Download patch'-> 'Branch' -> and paste this command into "
              "your terminal.")
    )
    xgroup.add_argument("-c", "--commit", type=str,
        help="Git commit hash to be checked. Default is current 'HEAD'",
        default="HEAD"
    )
    xgroup.add_argument("-f", "--file", type=str,
        help="Specific file to be checked. (Report is local)."
    )
    xgroup.add_argument("-F", "--files-list", type=str,
        help=("Check files, listed in file, specified by option. "
              "(Report is local).")
    )

    ap.add_argument("-u", "--user", type=str,
        help=("Gerrit user name. Default is name from {}/gerrit_settings.yaml".
              format(SCRIPT_DIR)),
        default=GERRIT_USER
    )
    ap.add_argument("-p", "--password", type=str,
        help='Gerrit HTTP password (from "HTTP Credentials" tab)',
        default=GERRIT_HTTP_CRED_PWD,
    )

    ap.add_argument("-a", "--analyzer",
        help="Analyzer to be launched",
        choices=list(analyzer_configs.keys()) + ["all"],
        default=["all"],
        action="append"
    )
    ap.add_argument("-l", "--local",
        help=("Output report locally instead of submitting it to Gerrit"),
        default=False,
        action="store_true"
    )
    ap.add_argument("--force_no_verify",
        help=("Allow requests with SSL verification disabled"),
        default=False,
        action="store_true"
    )
    return ap.parse_args()

def main():
    global GERRIT_URL_BASE
    args = parse_args();

    if args.force_no_verify:
        # Suppress only the InsecureRequestWarning from urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    auth = HTTPBasicAuth(args.user, args.password)
    restapi = GerritRestAPI(url=GERRIT_SERVER_URL, auth=auth,
                            verify=not args.force_no_verify)

    ch_api = ch.EndPoint(restapi)

    if args.url:
        GERRIT_URL_BASE = args.url.split('+')[0]
        commits = handle_url(args, ch_api)
    elif args.commit:
        handle_commit(args)
    elif args.file:
        handle_file(args)
    elif args.files_list:
        handle_flist(args)

    analyze(args, ch_api, commits)

if __name__ == "__main__":
    sys.exit(main())
