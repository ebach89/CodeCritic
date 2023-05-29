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

    def put_draft(self, change_id, revision_id, comments):
        """
        TODO: function must handle both:
          * Create Draft
        https://gerrit-documentation.storage.googleapis.com/Documentation/3.3.0/rest-api-changes.html#create-draft
        and
          * Update Draft (if script sees, that it tries to create a comment atop
            already existing one)
        https://gerrit-documentation.storage.googleapis.com/Documentation/3.3.0/rest-api-changes.html#update-draft
        TODO: in_reply_to can be used to answer in thread

        :comments is an array of elements with type CommentInput
        """
        url = f"/changes/{change_id}/revisions/{revision_id}/drafts"

        for comment in comments:
            CommentInfo = self.rest_api.put(url, return_response=True, json=comment)

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


def test_put_draft(changes_ep, change_id, revision_id):
    # see format here:
    # https://gerrit-documentation.storage.googleapis.com/Documentation/3.3.0/rest-api-changes.html#comment-input
    inline_comments = [
        {
            "path": "Makefile",
            "line": 42,
            "message": "line 42: inline comment from changes.py, posted as a draft",
        },
        {
            "path": "Makefile",
            "line": 43,
            "message": "line 43: inline comment from changes.py, posted as a draft",
        },
    ]
    changes_ep.put_draft(change_id, revision_id, inline_comments)


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
            * put_draft
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
    elif "put_draft" in args.test_case:
        revision_id = "6afbaf2e9538352d52018baab511b5d9153b554d"
        test_put_draft(changes, change_id, revision_id)


if __name__ == "__main__":
    sys.exit(main())
