*******************************
How to Get Your Change Into Ryu
*******************************

Submitting a change
===================

Send patches to ryu-devel@lists.sourceforge.net. Please don't use 'pull
request' on github. We expect you to send a patch in Linux kernel
development style. If you are not familiar with it, please read the
following document:

https://www.kernel.org/doc/Documentation/SubmittingPatches

Please check your changes with pep8 and run unittests to make sure
that they don't break the existing features. The following command
does both for you:

fujita@rose:~/git/ryu$ ./run_tests.sh

Of course, you are encouraged to add unittests when you add new
features (it's not a must though).

Python version and libraries
============================
* Python 2.6+
  As RHEL 6 adopted python 2.6, features only for 2.7+ should be avoided.

* standard library + widely used library
  Basically widely used == OpenStack adopted
  As usual there are exceptions. gevents. Or python binding library for other
  component.

Coding style guide
==================
* pep8
  As python is used, PEP8 is would be hopefully mandatory for
  http://www.python.org/dev/peps/pep-0008/

* pylint
  Although pylint is useful for finding bugs, but pylint score not very
  important for now because we're still at early development stage.

* Google python style guide is very helpful
  http://google-styleguide.googlecode.com/svn/trunk/pyguide.html

  Guidelines derived from Guido's Recommendations

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

* OpenStack Nova style guide
  https://github.com/openstack/nova/blob/master/HACKING.rst

* JSON files
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
