#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
# Copyright 2010 OpenStack LLC.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Installation script for Quantum's development virtualenv
"""

import os
import subprocess
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
VENV = os.path.join(ROOT, '.venv')
PIP_REQUIRES = os.path.join(ROOT, 'tools', 'pip-requires')
OPTIONAL_REQUIRES = os.path.join(ROOT, 'tools', 'optional-requires')
TEST_REQUIRES = os.path.join(ROOT, 'tools', 'test-requires')
PY_VERSION = "python%s.%s" % (sys.version_info[0], sys.version_info[1])

VENV_EXISTS = bool(os.path.exists(VENV))

def die(message, *args):
    print >> sys.stderr, message % args
    sys.exit(1)


def run_command(cmd, redirect_output=True, check_exit_code=True):
    """
    Runs a command in an out-of-process shell, returning the
    output of that command.  Working directory is ROOT.
    """
    if redirect_output:
        stdout = subprocess.PIPE
    else:
        stdout = None
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=stdout)
    output = proc.communicate()[0]
    if check_exit_code and proc.returncode != 0:
        raise Exception('Command "%s" failed.\n%s' % (' '.join(cmd), output))
    return output


HAS_EASY_INSTALL = bool(run_command(['which', 'easy_install'],
                                    check_exit_code=False).strip())
HAS_VIRTUALENV = bool(run_command(['which', 'virtualenv'],
                                    check_exit_code=False).strip())


def check_dependencies():
    """Make sure virtualenv is in the path."""

    if not HAS_VIRTUALENV:
        raise Exception('Virtualenv not found. ' + \
                         'Try installing python-virtualenv')
    print 'done.'


def create_virtualenv(venv=VENV, install_pip=False):
    """Creates the virtual environment and installs PIP only into the
    virtual environment
    """
    print 'Creating venv...',

    install = ['virtualenv', '-q', venv]
    run_command(install)

    print 'done.'
    print 'Installing pip in virtualenv...',
    if install_pip and \
            not run_command(['tools/with_venv.sh', 'easy_install',
                             'pip>1.0']):
        die("Failed to install pip.")
    print 'done.'


def install_dependencies(venv=VENV):
    print 'Installing dependencies with pip (this can take a while)...'
    run_command(['tools/with_venv.sh', 'pip', 'install', '-r',
                 PIP_REQUIRES], redirect_output=False)
    run_command(['tools/with_venv.sh', 'pip', 'install', '-r',
                 OPTIONAL_REQUIRES], redirect_output=False)
    run_command(['tools/with_venv.sh', 'pip', 'install', '-r',
                 TEST_REQUIRES], redirect_output=False)

    # Tell the virtual env how to "import quantum"
    pthfile = os.path.join(venv, "lib", PY_VERSION, "site-packages",
                                 "quantum.pth")
    f = open(pthfile, 'w')
    f.write("%s\n" % ROOT)


def print_help():
    help = """
 Quantum development environment setup is complete.

 Quantum development uses virtualenv to track and manage Python dependencies
 while in development and testing.

 To activate the Quantum virtualenv for the extent of your current shell
 session you can run:

 $ source .venv/bin/activate

 Or, if you prefer, you can run commands in the virtualenv on a case by case
 basis by running:

 $ tools/with_venv.sh <your command>

 Also, make test will automatically use the virtualenv.
    """
    print help


def main(argv):
    check_dependencies()
    create_virtualenv()
    install_dependencies()
    print_help()

if __name__ == '__main__':
    main(sys.argv)
