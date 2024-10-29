#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -e
set -o pipefail

if systemd-analyze --offline=true security 2>/dev/null </dev/null; then

	# We're using "security" as opposed to "verify" because (as of 2024)
	# the latter doesn't support --offline runs.
	#
	# The point is that if anything appears before the security report
	# header, there's an error or a warning while parsing the unit file.
	env -i systemd-analyze --offline=true security "$1" 2>&1 |awk '
		/NAME.*DESCRIPTION.*EXPOSURE/ {suppress=1}
		{if (!suppress) {print; failed++}}
		END {exit failed}
	'

else
	echo "SKIP: systemd-analyze --offline=true security not supported" >&2
fi
