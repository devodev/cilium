#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-upstream/main}"
ORIGIN_BRANCH="${ORIGIN_BRANCH:-origin/main-ce}"

# Directories to exclude from the check.
excluded_dirs=(vendor Documentation/cmdref)

# List new files outside excluded directories compared to main-ce.
new_files=$(git diff --name-only --diff-filter=A "${ORIGIN_BRANCH}"...HEAD -- . "${excluded_dirs[@]/#/:^}")
code_owners=$(go tool github.com/hmarr/codeowners/cmd/codeowners)

unowned_enterprise_files=()
for file in ${new_files}; do
  # Check if this new file exists in upstream.
  if ! git ls-tree -r --name-only "${UPSTREAM_BRANCH}" | grep "^${file}$" > /dev/null; then
    # if it doesn't exist in upstream, check if it's owned by a team in isovalent org.
    if echo "${code_owners}" | grep "^${file} " | grep -qv "@isovalent/"; then
      unowned_enterprise_files+=("$file")
    fi
  fi
done

if [ ${#unowned_enterprise_files[@]} -gt 0 ]; then
    echo "Add entries to CODEOWNERS for these newly added enterprise-only files:"
    printf "%s\n" "${unowned_enterprise_files[@]}"
    exit 1
fi
