PyBal is a LVS monitor. It monitors HTTP or DNS servers and adapts LVS state
based on the results. PyBal was created for use by Wikimedia.

[![Build Status](https://travis-ci.org/wikimedia/PyBal.svg?branch=master)](https://travis-ci.org/wikimedia/PyBal)
[![Coverage Status](https://img.shields.io/coveralls/wikimedia/PyBal.svg)](https://coveralls.io/r/wikimedia/PyBal?branch=master)

Unit tests are available under pybal/test/. To run the unit tests and get a
coverage report:

    pip install -r requirements.txt
    coverage run --source=pybal setup.py test && coverage report
