#!/usr/bin/env python3

import argparse
import sys
import utilpy.cfg.yamlmisc as yamlm

from pygerrit2 import GerritRestAPI, HTTPBasicAuth

GERRIT_URL = '<URL to your gerrit>'
GERRIT_HTTP_CRED_PWD = 'Go Settings->HTTP Credentials->Generate New Password'


def main(args):
    username = args.user
    password = args.password

    auth = HTTPBasicAuth(username, password)
    restapi = GerritRestAPI(url=GERRIT_URL, auth=auth)

    change_id = "Ia82b0250676fecb3cabcbcf5ae5270d963c7a670"
    ## revision 1 == Patchset 1 (in gerrit terms)
    #revision_id = "37d5a1d54b87e985336f93e8be6fe4eaf16d979c"
    revision_id = 1
    message = 'Your comment on revision_id=1 (adding cfg.yaml)'
    # revision 2
    #revision_id = "6afbaf2e9538352d52018baab511b5d9153b554d"
    #message = 'Your review comment'

    data = {"message": message}
    url = f"/changes/{change_id}/revisions/{revision_id}/review"
    restapi.post(url, json=data)


if __name__ == "__main__":

    conf = yamlm.load_config("../../gerrit_settings.yaml")
    GERRIT_URL = conf['GERRIT_URL']
    GERRIT_HTTP_CRED_PWD = conf['GERRIT_HTTP_CRED_PWD']

    ap = argparse.ArgumentParser(description='Push a comment on Gerrit review')

    ap.add_argument('--user', type=str, help='Gerrit user name', required=True)
    ap.add_argument('--password', type=str,
            help='Gerrit HTTP password (from "HTTP Credentials" tab)',
            default=GERRIT_HTTP_CRED_PWD)
    args = ap.parse_args()

    sys.exit(main(args))
