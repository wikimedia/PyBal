"""
PyBal
~~~~~

PyBal is a cluster monitoring daemon. It executes health checks against
servers and updates LVS connection tables accordingly. PyBal is used in
production at Wikimedia.

"""
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


setup(
    name='PyBal',
    version='1.14',
    license='GPLv2+',
    author='Mark Bergsma',
    author_email='mark@wikimedia.org',
    url='https://wikitech.wikimedia.org/wiki/PyBal',
    description='PyBal LVS monitor',
    long_description=__doc__,
    classifiers=(
        'Development Status :: 5 - Production/Stable',
        'Framework :: Twisted',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: '
            'GNU General Public License v2 or later (GPLv2+)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: System :: Networking :: Monitoring',
    ),
    packages=(
        'pybal',
        'pybal.bgp',
        'pybal.monitors',
    ),
    scripts=(
        'scripts/pybal',
    ),
    requires=(
        'twisted',
        'PyOpenSSL'
    ),
    tests_require=(
        'mock',
    ),
    test_suite='pybal.test',
    zip_safe=False,
)
