Ensure your pull request adheres to the following guidelines:

- [ ] Set one of the following labels:

  - `release-note/major`: For pull requests that introduce major features.
  - `release-note/minor`: For pull requests that introduce minor features.
  - `release-note/misc`: For miscellaneous pull requests.
  - `release-note/bug`: For pull requests to fix bugs in enterprise features.
  - `release-note/ignore`: For pull requests that are not customer-facing, like
    updating `CODEOWNERS` file. Pull requests with this label will not show up
    in release notes.
  - `release-note/enterprise-backport`: For backport pull requests from main-ce branch.
  - `release-note/oss-sync`: For pull requests to sync from an OSS branch.
  - `release-note/oss-backport`: For pull requests to backport OSS commits that
     are not being backported to the corresponding OSS stable branch.

- [ ] Provide a release-note blurb, or the pull request title will be used as a
      release note entry. Either way, the release note entry must be appropriate
      as an entry in customer-facing release notes unless `release-note/ignore`
      label is set.

<!-- Description of change -->

Fixes: #issue-number

```release-note
<!-- Enter the release note text here or remove this release-note section from your PR description. Do NOT put an "empty" release note here -->
```
