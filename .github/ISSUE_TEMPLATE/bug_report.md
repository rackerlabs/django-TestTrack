---
name: Bug report
about: Create a report to help us improve
title: ''
labels: bug
assignees: ''

---
**Slack us first!**
The easiest and fastest way to help you is via Slack. There's a free and easy signup to join our #defectdojo channel in the OWASP Slack workspace: [Get Access.](https://owasp.org/slack/invite)
If you're confident you've found a bug, or are allergic to Slack, you can submit an issue anyway.

**Be informative**
Please enter as much information as possible, otherwise we can't provide support. If possible upgrade to the latest release or dev version and try again.

**Bug description**
A clear and concise description of what the bug is. For errors include at least the exact error message you are seeing (including traceback).

**Steps to reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Deployment method** *(select with an `X`)*
- [ ] Docker Compose
- [ ] Kubernetes
- [ ] GoDojo

**Environment information**
 - Operating System: [e.g. Ubuntu 18.04]
 - Docker Compose or Helm version (Output of `docker compose version` or `helm version`)
 - DefectDojo version (see footer) or commit message: [use `git show -s --format="[%ci] %h: %s [%d]"`]

**Logs** 
Use `docker compose logs` (or similar, depending on your deployment method) to get the logs and add the relevant sections here showing the error occurring (if applicable).

**Sample scan files**
If applicable, add sample scan files to help reproduce your problem.

**Screenshots**
If applicable, add screenshots to help explain your problem.

**Additional context** (optional)
Add any other context about the problem here.
