PyBal is a LVS monitor. It monitors HTTP or DNS servers and adapts LVS state
based on the results. PyBal was created for use by Wikimedia.

[![Build Status](https://travis-ci.org/wikimedia/PyBal.svg?branch=master)](https://travis-ci.org/wikimedia/PyBal)
[![Coverage Status](https://img.shields.io/coveralls/wikimedia/PyBal.svg)](https://coveralls.io/r/wikimedia/PyBal?branch=master)

Unit tests are available under pybal/test/. To run the unit tests and get a
coverage report:

    pip install -r requirements.txt
    coverage run --source=pybal setup.py test && coverage report

Branching/release policy
-------------

Since PyBal is a mission-critical software and a bug can bring down
the whole infrastructure, we try to minimize the risk by avoiding
having to release large changes when we want to bring a bugfix to
production. In order to do so, we do the following:

- We adopt [semantic versioning 2.0 ](http://semver.org/) so we change
  the major version for API breaking changes, the minor version for
  adding new functionality, and the patch version for bugfixes.
- All development of non breaking new features should happen against
  the master branch, with the exception of minor version-specific
  bugfixes
- Breaking changes (ones that would trigger a major revision change)
  should first be developed in a separate development branch named
  X.0-dev. It will be merged back into master once we're ready to move
  to a new major release. This way we can work on/test the breaking
  change while not stopping further development of incremental
  improvements on the current codebase.
- Whenever we're happy with the new functionality in master and we
  think we're ready to take that to production, we create a branch
  named as the minor version (e.g. "1.09"). We'll call these the
  "release branches".
- When we make a bugfix that applies to the code in master as well, we
  do the CR/merge on the master branch, and then we cherry-pick the
  change to the release branches currently maintained.
  If the bugfix is specific to a release branch (because, for example,
  the code in master has been rewritten/replaced), we just post it
  against the release branch.
- New versions should always come from release branches.
- When we decide we don't actively maintain a minor version, a commit
  to the release branch should be done indicating that.

So let's review how a typical bugfix workflow works:

- The patch to fix the bug is developed and reviewed on master.
- Once it's merged on master, the patch is cherry-picked to the
  release branches and either merged (if the cherry-pick is clean) or
  re-reviewed: please apply common sense
- When we're happy with the patch, we create the debian/changelog
  entry on the release branch. This entry will need to be reintegrated
  back to the debian/changelog on master, most probably manually in a
  separate commit.

If your commit is instead adding a new functionality, it should definitely go
to master. If it's introducing breaking changes, it goes to the
X.0-dev branch currently under development.
