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

GERRIT_SERVER_URL = ""
SCRIPT_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))
CUR_DIR = os.getcwd()

GERRIT_URL_BASE = None
# Make shell utils ready
git = local["git"]
bash = local["bash"]
CXX_HDR_FILES = [".hpp"]
CXX_SRC_FILES = [".cc", ".cpp"]
CXX_FILES = CXX_HDR_FILES + CXX_SRC_FILES
C_HDR_FILES = [".h"]
C_SRC_FILES = [".c"]
C_FILES = C_HDR_FILES + C_SRC_FILES

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


def filter_files(files, suffixes):
    """
    files: list of files
    """
    result = []
    for afile in files:
        if afile.endswith(suffixes) and os.path.exists(afile):
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

def run_cppcheck(commits, files_filter, lang):
    """ Runs cppcheck on a list of files changed in every 'commit' in 'commits'
    and updates a 'commits' dict with al necessary info, required for Gerrit to
    submit a review comments. Function reports only those errors, which belong
    to the changes in particular 'commit'.
    """
    print(f"run_cppcheck() for files: {files_filter}")

    cppcheck = "cppcheck"
    if os.path.exists(f"{SCRIPT_DIR}/analyzers.yaml"):
        cfg = yamlm.load_config(f"{SCRIPT_DIR}/analyzers.yaml")
        try:
            if cfg is not None:
                cppcheck = cfg['CPPCHECK']
        except KeyError as ex:
            # Preserve original name
            pass

    cppcheck = local[cppcheck][
        "--quiet", "--enable=all", "--inconclusive", "-f",
        f"--language={lang}",
        "--template={file}###{line}###{severity}###{message}"]

    for commit in commits:
        print(f"\n=== Analyze: {commit['subject']}")
        commit['report'] = {}

        git("checkout", commit['git_hash'])
        ret, out, err = cppcheck.run(filter_files(commit['files'],
                                                  files_filter),
                                     retcode=None)

        if ret != 0:
            print("Review: {}".format(commit['url']))
            print("\tSubject: {}".format(commit['subject']))
            print(f"\t\t[CPPCHECK] failed with err:{ret}")
            print(f"stderr:\n\t{err}")
            print(f"stdout:\n\t{out}")
            continue

        if len(err) == 0:
            print("Review: {}".format(commit['url']))
            print("\tSubject: {}".format(commit['subject']))
            print("\t\t[CPPCHECK] has NO problems.")
            continue


        # Each stderr line is an issue
        report = {}
        # "message" is printed not in-file (i.e. as Reply to whole patch)
        # Uncomment line below, when you will be ready to reveal yourself
        # as person, using Gerra & CodeCritic
        #report["message"] = "[CPPCHECK] Some issues need to be fixed."
        report["message"] = "I've found some issues"

        report["comments"] = defaultdict(list)
        for line in err.strip().split("\n"):
            if len(line.strip()) == 0:
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

        commit['report'].update(report)

def run_cppcheck_c(commits):
    run_cppcheck(commits, tuple(C_FILES), "c")

def run_cppcheck_cxx(commits):
    run_cppcheck(commits, tuple(CXX_FILES), "c++")

def run_cpplint(commits):
    print("run_cpplint() called")
    pass

def run_flake8(commits):
    PY_FILES = [".py"]
    files_filter = tuple(PY_FILES)

    print("run_flake8() called")

    flake8 = "flake8"
    if os.path.exists(f"{SCRIPT_DIR}/analyzers.yaml"):
        cfg = yamlm.load_config(f"{SCRIPT_DIR}/analyzers.yaml")
        try:
            if cfg is not None:
                flake8 = cfg['FLAKE8']
        except KeyError as ex:
            # Preserve original name
            pass

    flake8 = local[flake8][
        "--exit-zero",
        "--format=%(path)s###%(row)d###%(code)s###%(text)s"]

    for commit in commits:
        print(f"\n=== Analyze: {commit['subject']}")
        commit['report'] = {}

        git("checkout", commit['git_hash'])
        ret, out, err = flake8.run(filter_files(commit['files'],
                                                files_filter),
                                   retcode=None)

        if ret != 0:
            print("Review: {}".format(commit['url']))
            print("\tSubject: {}".format(commit['subject']))
            print(f"\t\t[flake8] failed with err:{ret}")
            print(f"stderr:\n\t{err}")
            print(f"stdout:\n\t{out}")
            continue

        # cppcheck (stderr), flake8 (stdout)!!!
        if len(out) == 0:
            print("Review: {}".format(commit['url']))
            print("\tSubject: {}".format(commit['subject']))
            print("\t\t[flake8] has NO problems.")
            continue


        # Each stderr line is an issue
        report = {}
        # "message" is printed not in-file (i.e. as Reply to whole patch)
        # Uncomment line below, when you will be ready to reveal yourself
        # as person, using Gerra & CodeCritic
        #report["message"] = "[flake8] Some issues need to be fixed."
        report["message"] = "I've found some issues"

        report["comments"] = defaultdict(list)
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

        commit['report'].update(report)

ANALYZERS_MAP = {
    "cppcheck_c": run_cppcheck_c,
    "cppcheck_cxx": run_cppcheck_cxx,
    ###"cpplint": run_cpplint,
    "flake8": run_flake8
}

def analyze(args, ch_api, commits):

    analyzers = []
    if "all" in args.analyzer and len(args.analyzer) > 1:
        args.analyzer.remove("all")
        analyzers.extend(args.analyzer)
    elif "all" in args.analyzer and len(args.analyzer) == 1:
        analyzers.extend(ANALYZERS_MAP.keys())

    for a in analyzers:
        ANALYZERS_MAP[a](commits)

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
        choices=list(ANALYZERS_MAP.keys()) + ["all"],
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
