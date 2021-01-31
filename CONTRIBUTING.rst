*******************************
How to Get Your Change Into Ryu
*******************************

Submitting a change
===================

To send patches to ryu, please make a
`pull request <https://github.com/faucetsdn/ryu>`_ on GitHub.

Please check your changes with autopep8, pycodestyle(pep8) and running
unit tests to make sure that they don't break the existing features.
The following command does all for you.

.. code-block:: bash

  # Install dependencies of tests
  $ pip install -r tools/test-requires

  # Execute autopep8
  # Also, it is convenient to add settings of your editor or IDE for
  # applying autopep8 automatically.
  $ autopep8 --recursive --in-place ryu/

  # Execute unit tests and pycodestyle(pep8)
  $ ./run_tests.sh

Of course, you are encouraged to add unit tests when you add new
features (it's not a must though).

Python version and libraries
============================
* Python 3.5, 3.6, 3.7, 3.8, 3.9:

  Ryu supports multiple Python versions.  CI tests on GitHub Actions is running
  on these versions.

* standard library + widely used library:

  Basically widely used == OpenStack adopted.
  As usual there are exceptions.  Or python binding library for other
  component.

Coding style guide
==================
* pep8:

  As python is used, PEP8 is would be hopefully mandatory for
  https://www.python.org/dev/peps/pep-0008/

* pylint:

  Although pylint is useful for finding bugs, but pylint score not very
  important for now because we're still at early development stage.
  https://www.pylint.org/

* Google python style guide is very helpful:
  http://google.github.io/styleguide/pyguide.html

* Guidelines derived from Guido's Recommendations:

  =============================   =================   ========
  Type                            Public              Internal
  =============================   =================   ========
  Packages                        lower_with_under
  Modules                         lower_with_under    _lower_with_under
  Classes                         CapWords            _CapWords
  Exceptions                      CapWords
  Functions                       lower_with_under()  _lower_with_under()
  Global/Class Constants          CAPS_WITH_UNDER     _CAPS_WITH_UNDER
  Global/Class Variables          lower_with_under    _lower_with_under
  Instance Variables              lower_with_under    _lower_with_under (protected) or __lower_with_under (private)
  Method Names                    lower_with_under()  _lower_with_under() (protected) or __lower_with_under() (private)
  Function/Method Parameters      lower_with_under
  Local Variables                 lower_with_under
  =============================   =================   ========

* OpenStack Nova style guide:
  https://github.com/openstack/nova/blob/master/HACKING.rst

* JSON files:

  Ryu source tree has JSON files under ryu/tests/unit/ofproto/json.
  They are used by unit tests.  To make patches easier to read,
  they are normalized using tools/normalize_json.py.  Please re-run
  the script before committing changes to these JSON files.

Reference
=========
* Python Essential Reference, 4th Edition [Amazon]
  * Paperback: 717 pages
  * Publisher: Addison-Wesley Professional; 4 edition (July 19, 2009)
  * Language: English
  * ISBN-10: 0672329786
  * ISBN-13: 978-0672329784

* The Python Standard Library by Example (Developer's Library)
  * Paperback: 1344 pages
  * Publisher: Addison-Wesley Professional; 1 edition (June 11, 2011)
  * Language: English
  * ISBN-10: 0321767349
  * ISBN-13: 978-0321767349
