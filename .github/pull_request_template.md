## :warning: Note on feature completeness :warning:

We are narrowing the scope of acceptable enhancements to DefectDojo in preparation for v3. Learn more here:
https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/CONTRIBUTING.md

**Description**

Describe the feature / bug fix implemented by this PR.
If this is a new parser, [the parser guide](https://documentation.defectdojo.com/contributing/how-to-write-a-parser/) may be worth (re)reading.

**Test results**

Ideally you extend the test suite in `tests/` and `dojo/unittests` to cover the changed in this PR.
Alternatively, describe what you have and haven't tested.

**Documentation**

Please update any documentation when needed in the [documentation folder](https://github.com/DefectDojo/django-DefectDojo/tree/dev/docs))

**Checklist**

This checklist is for your information.

- [ ] Make sure to rebase your PR against the very latest `dev`.
- [ ] Features/Changes should be submitted against the `dev`.
- [ ] Bugfixes should be submitted against the `bugfix` branch.
- [ ] Give a meaningful name to your PR, as it may end up being used in the release notes.
- [ ] Your code is flake8 compliant.
- [ ] Your code is python 3.11 compliant.
- [ ] If this is a new feature and not a bug fix, you've included the proper documentation in the docs at https://github.com/DefectDojo/django-DefectDojo/tree/dev/docs as part of this PR.
- [ ] Model changes must include the necessary migrations in the dojo/db_migrations folder.
- [ ] Add applicable tests to the unit tests.
- [ ] Add the proper label to categorize your PR.

**Extra information**

Please clear everything below when submitting your pull request, it's here purely for your information.

Moderators: Labels currently accepted for PRs:
- Import Scans (for new scanners/importers)
- enhancement
- performance
- feature
- bugfix
- maintenance (a.k.a chores)
- dependencies
- New Migration (when the PR introduces a DB migration)
- settings_changes (when the PR introduces changes or new settings in settings_dist.py)

# Contributors: Git Tips
## Rebase on dev branch
If the dev branch has changed since you started working on it, please rebase your work after the current dev.

On your working branch `mybranch`:
```
git rebase dev mybranch
```
In case of conflict:
```
 git mergetool
 git rebase --continue
 ```

When everything's fine on your local branch, force push to your `myOrigin` remote:
```
git push myOrigin --force-with-lease
```

To cancel everything:
```
git rebase --abort
```


## Squashing commits
```
git rebase -i origin/dev
```
- Replace `pick` by `fixup` on the commits you want squashed out
- Replace `pick` by `reword` on the first commit if you want to change the commit message
- Save the file and quit your editor

Force push to your `myOrigin` remote:
```
git push myOrigin --force-with-lease
```
