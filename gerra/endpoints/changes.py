#!/usr/bin/env python3

import sys
from pygerrit2 import GerritReview


class EndPoint:
    name = "/changes"

    def __init__(self, gerrit_api):
        self.rest_api = gerrit_api

    def post_review(self, change_id, revision_id, tag, labels, message, comments):
        """
        https://github.com/dpursehouse/pygerrit2/blob/4a54d0be22bb1fef91d4dc62a4547fc1ae92eacd/pygerrit2/rest/__init__.py#L285
        comments in the form of: list of dict in 2 flavors:
            add_comments([{'filename': 'Makefile',
                           'line': 10,
                           'message': 'inline message'}])

            add_comments([{'filename': 'Makefile',
                           'range': {'start_line': 0,
                                     'start_character': 1,
                                     'end_line': 0,
                                     'end_character': 5},
                           'message': 'inline message'}])
        """
        # 'POST /changes/{change-id}/revisions/{revision-id}/review'
        # Form a ReviewInput entity:
        review_input = GerritReview()
        # Set review tag (str)
        review_input.set_tag(tag)
        # add_labels({'Verified': 1, 'Code-Review': -1})
        review_input.add_labels(labels)
        # Set review cover message (str)
        review_input.set_message(message)
        # Add inline comments (?? dict OR list of dicts ??)
        review_input.add_comments(comments)

        # Get ?ReviewResult entity? OR 'JSON decoded result of ReviewResult' as output
        ReviewResult = self.rest_api.review(change_id, revision_id, review_input)

    def get_patch():
        # 'GET /changes/{change-id}/revisions/{revision-id}/patch'
        pass


def test_post_review(changes_ep, change_id, revision_id):
    # Hard-coded values
    # TODO: get rid of them
    labels = {"Code-Review": -1}
    cover_msg = "Testing the gerra"
    inline_comments = [
        {
            "filename": "Makefile",
            "line": 255,
            "message": "inline comment test on 255 from changes.py",
        },
        {
            "filename": "Makefile",
            "line": 256,
            "message": "inline comment test on 256 from changes.py",
        },
    ]
    changes_ep.post_review(
        change_id, revision_id, None, labels, cover_msg, inline_comments
    )


def main():
    import argparse
    import utilpy.cfg.yamlmisc as yamlm

    from pygerrit2 import GerritRestAPI, HTTPBasicAuth

    conf = yamlm.load_config("../../gerrit_settings.yaml")
    GERRIT_URL = conf["GERRIT_URL"]
    GERRIT_HTTP_CRED_PWD = conf["GERRIT_HTTP_CRED_PWD"]

    ap = argparse.ArgumentParser(description="Push a Review for patch-set on Gerrit")
    ap.add_argument(
        "--password",
        type=str,
        help='Gerrit HTTP password (from "HTTP Credentials" tab)',
        default=GERRIT_HTTP_CRED_PWD,
    )

    ap.add_argument("--user", type=str, help="Gerrit user name", required=True)
    ap.add_argument(
        "--test-case",
        type=str,
        help="""test-case name to launch:
            * post_review
            """,
    )
    args = ap.parse_args()

    auth = HTTPBasicAuth(args.user, args.password)
    restapi = GerritRestAPI(url=GERRIT_URL, auth=auth)

    changes = EndPoint(restapi)

    change_id = "Ia82b0250676fecb3cabcbcf5ae5270d963c7a670"
    ## revision 1 == Patchset 1 (in gerrit terms)
    # revision_id = "37d5a1d54b87e985336f93e8be6fe4eaf16d979c"
    # revision_id = 1

    ## revision 2
    # revision_id = "6afbaf2e9538352d52018baab511b5d9153b554d"
    revision_id = 2

    if "post_review" in args.test_case:
        test_post_review(changes, change_id, revision_id)


if __name__ == "__main__":
    sys.exit(main())
