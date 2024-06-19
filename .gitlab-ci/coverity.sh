#!/bin/bash
set -e

[ "$COVERITY_SCAN_PROJECT_NAME" = "" ] && echo "missing COVERITY_SCAN_PROJECT_NAME" >&2 && exit 1
[ "$COVERITY_SCAN_TOKEN" = "" ] && echo "missing COVERITY_SCAN_PROJECT_NAME" >&2 && exit 1

if [ "$1" = "download" ]; then
    curl https://scan.coverity.com/download/linux64 \
         -o /tmp/cov-analysis-linux64.tar.gz        \
         --form "project=$COVERITY_SCAN_PROJECT_NAME" \
         --form "token=$COVERITY_SCAN_TOKEN"

    tar xvzf /tmp/cov-analysis-linux64.tar.gz
elif [ "$1" = "upload" ]; then
    tar cvzf cov-int.tar.gz cov-int
    ls -l cov-int.tar.gz
    curl "https://scan.coverity.com/builds?project=$COVERITY_SCAN_PROJECT_NAME" \
          --form "token=$COVERITY_SCAN_TOKEN" --form "email=$GITLAB_USER_EMAIL" \
          --form file=@cov-int.tar.gz --form version="`meson introspect --projectinfo | jq -r .version`" \
          --form description="ci run: $CI_COMMIT_TITLE / `git rev-parse --short HEAD`"
    rm -rf cov-int*
else
    echo "invalid command: $1" >&2
    exit 1
fi