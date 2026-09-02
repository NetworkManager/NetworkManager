#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# Checks the merge request description for the marker that AGENTS.md
# requires AI agents to emit when they generate contributor communication.
# The variable is only set in merge request pipelines.

CANARY='biblioklept'

desc="${CI_MERGE_REQUEST_DESCRIPTION:-}"

[ -n "$desc" ] || exit 0

if [ "${CI_MERGE_REQUEST_DESCRIPTION_IS_TRUNCATED:-}" = "true" ]; then
    printf 'note: GitLab truncated the description at 2700 characters; only that part is checked\n' >&2
fi

if grep -qiF "$CANARY" <<< "$desc"; then
    printf '%s\n' >&2 \
        'ERROR: the merge request description contains the marker that' \
        'AGENTS.md requires agents to leave in text they generate. Per' \
        'AGENTS.md and CONTRIBUTING.md, the description must be written by' \
        'the human author. Rewrite it in your own words, disclose any AI' \
        'assistance, then re-run the pipeline.'
    exit 1
fi
