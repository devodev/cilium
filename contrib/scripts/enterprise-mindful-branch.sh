#!/bin/bash

set -eu
set -o pipefail

UPSTREAM_REPO="cilium\/cilium"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-main}"
DOWNSTREAM_BRANCH="${DOWNSTREAM_BRANCH:-HEAD}"

COMMITS=()

function usage() {
  echo -e "$0 [FLAGS]"
  echo
  echo -e 'Create a git branch from the merge-base of the upstream tree and'
  echo -e 'cherry-pick commits that have been manually applied to the'
  echo -e 'downstream tree.'
  echo
  echo -e 'Flags:'
  echo -e '-b | --branch\t\tName for new branch (default: "sync/<COMMIT>-<DATE>")'
  echo -e '-d | --debug\t\tRun the script with debug output (-x)'
  echo -e '   | --downstream-branch\tDevelopment branch (default: '"$DOWNSTREAM_BRANCH"')'
  echo -e '-f | --fetch\t\tFetch the latest upstream repo when preparing branch'
  echo -e '-h | --help\t\tDisplay this help message'
  echo -e '     --ignore-missing\tContinue even if upstream commits cannot be found'
  echo -e '     --ignore-failures\tContinue even if upstream commits cannot be merged'
  echo -e '-r | --repo\tSpecify the target repository to sync (example: "cilium/cilium")'
  echo -e '     --upstream-branch\tBranch used as a base (default: '"$UPSTREAM_BRANCH"')'
}

function find_commits() {
  merge_commit="$1"
  upstream_commit="$2"
  ignore_missing="$3"

  # Support the following syntaxes for upstream commit shas:
  #   [ upstream commit xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx ]
  # (cherry picked from commit xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)
  for commit in $(git log --reverse "$merge_commit"..."$DOWNSTREAM_BRANCH" \
                  | awk '/^\s*\[ upstream commit/ { print $4 } ; /^\s*\(cherry picked from commit/ { print $5 }' \
                  | cut -d')' -f1);
  do
    if ! git cat-file -e "$commit^{commit}"; then
        >&2 echo "Unknown commit: $commit"
        if [[ -z "$ignore_missing" ]]; then
          >&2 echo
          >&2 echo "Is this commit available in $upstream_commit branch?"
          exit 1
        fi
        continue
    fi
    COMMITS+=("$commit")
  done

  >&2 echo "Found ${#COMMITS[@]} upstream commits applied to $DOWNSTREAM_BRANCH since $merge_commit:"
  for commit in "${COMMITS[@]}"; do
      >&2 git log --oneline -1 "$commit"
  done
}

function create_branch() {
  branch="$1"
  merge_base="$2"
  ignore_failures="$3"

  git checkout -b "$branch" "$merge_base"
  if [[ -n $ignore_failures ]]; then
    for commit in "${COMMITS[@]}"; do
        contrib/backporting/cherry-pick "$commit" \
        || (git am --show-current-patch=diff && git am --abort)
    done
  elif [ ${#COMMITS[@]} -gt 0 ]; then
    contrib/backporting/cherry-pick "${COMMITS[@]}"
  fi
  git checkout -
}

function main() {
  local branch="" debug="" fetch="" ignore_missing="" ignore_failures=""
  local merge_base="" merge_commit="" upstream_commit="" upstream_remote=""

  set +e
  while [[ $# -gt 0 ]]; do
    case $1 in
      -b|--branch)
        branch="$2"
        shift;
        ;;
      -d|--debug)
        debug=1
        ;;
      --downstream-branch)
        DOWNSTREAM_BRANCH="$2"
        shift
        ;;
      -f|--fetch)
        fetch=1
        ;;
      -h|--help)
        >&2 usage
        exit 0
        ;;
      --ignore-missing)
        ignore_missing=1
        ;;
      --ignore-failures)
        ignore_failures=1
        ;;
      -r|--repo)
        UPSTREAM_REPO="$2"
        shift
        ;;
      -u|--upstream-branch)
        UPSTREAM_BRANCH="$2"
        shift
        ;;
      -*)
        >&2 echo "unknown option: $1"
        >&2 usage
        exit 1
        ;;
      *)
        if [[ $# -gt 0 ]]; then
          >&2 echo "Unrecognized args: $*"
          >&2 usage
          exit 1
        fi
    esac
    shift
  done
  set -e

  if [[ -n "$debug" ]]; then
      set -x
  fi

  upstream_remote=$(git remote -v \
                    | grep "${UPSTREAM_REPO}.*fetch" \
                    | awk '{ print $1; }')
  if [[ -n "$fetch" ]]; then
    git fetch --quiet "$upstream_remote"
  fi

  upstream_commit="$upstream_remote/${UPSTREAM_BRANCH}"
  merge_base=$(git merge-base "$upstream_commit" "$DOWNSTREAM_BRANCH")
  merge_commit=$(git rev-list "$merge_base"..."$DOWNSTREAM_BRANCH" \
                              --ancestry-path --merges --reverse \
                 | sed -n "1,1p")

  if [[ -z "$branch" ]]; then
    date="$(date --rfc-3339=date)"
    branch="sync/$merge_base-$date"
  fi
  if git show-branch "$branch" 2>/dev/null ; then
      >&2 echo "Branch $branch already exists, exiting"
      exit 1
  fi

  find_commits "$merge_commit" "$upstream_commit" "$ignore_missing"
  create_branch "$branch" "$merge_base" "$ignore_failures"

  >&2 echo "Use 'contrib/scripts/enterprise-meditation.sh $branch' to evaluate mindfulness."
}

main "$@"
