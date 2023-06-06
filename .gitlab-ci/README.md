.gitlab-ci
==========

We run tests in the gitlab-ci pipeline at
https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/pipelines

This directory contains a template for generating [.gitlab-ci.yml](../.gitlab-ci.yml).

It uses [ci-templates](https://gitlab.freedesktop.org/freedesktop/ci-templates/) project.

To get the right version of ci-templates, see the "Regenerate with" comment in
[.gitlab-ci.yml](../.gitlab-ci.yml).  It shows how to install ci-fairy via
python pip.  The exact version to be used is hard-coded as `.templates_sha`
variable in ci.template file.

Whenever changing relevant files, .gitlab-ci.yml must be regenerated.
Regenerate the yml by running `ci-fairy generate-template`.

There are also tests for checking that the yml is correct:

1) run `tools/check-gitlab-ci.sh`
2) run `make check-local-gitlab-ci`, which runs 1). This also
  runs as part of `make check`.

In both cases, the test is skipped if `ci-fairy` is not in the path.
Install the correct `ci-fairy` version.

In gitlab-ci pipeline, the "check-tree" test also checks that .gitlab-ci.yml
is up to date.
