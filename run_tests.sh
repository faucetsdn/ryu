#!/bin/sh

if [ -z "${PYTHON}" ]; then
  PYTHON=python
fi

usage() {
  echo "Usage: $0 [OPTION]..."
  echo "Run Ryu's test suite(s)"
  echo ""
  echo "  -V, --virtual-env                Always use virtualenv.  Install automatically if not present"
  echo "  -N, --no-virtual-env             Don't use virtualenv.  Run tests in local environment"
  echo "  -c, --coverage                   Generate coverage report"
  echo "  -f, --force                      Force a clean re-build of the virtual environment. Useful when dependencies have been added."
  echo "  -p, --pycodestyle, --pep8        Just run pycodestyle(pep8)"
  echo "  -P, --no-pycodestyle, --no-pep8  Don't run pycodestyle(pep8)"
  echo "  -l, --pylint                     Just run pylint"
  echo "  -i, --integrated                 Run integrated test"
  echo "  -v, --verbose                    Run verbose pylint analysis"
  echo "  -h, --help                       Print this usage message"
  echo ""
  echo "Note: with no options specified, the script will try to run the tests in a virtual environment,"
  echo "      If no virtualenv is found, the script will ask if you would like to create one.  If you "
  echo "      prefer to run tests NOT in a virtual environment, simply pass the -N option."
  exit
}

process_option() {
  case "$1" in
    -h|--help) usage;;
    -V|--virtual-env) always_venv=1; never_venv=0;;
    -N|--no-virtual-env) always_venv=0; never_venv=1;;
    -f|--force) force=1;;
    -p|--pycodestyle|--pep8) just_pycodestyle=1; never_venv=1; always_venv=0;;
    -P|--no-pycodestyle|--no-pep8) no_pycodestyle=1;;
    -l|--pylint) just_pylint=1;;
    -i|--integrated) integrated=1;;
    -c|--coverage) coverage=1;;
    -v|--verbose) verbose=1;;
    -*) noseopts="$noseopts $1";;
    *) noseargs="$noseargs $1"
  esac
}

venv=.venv
with_venv=tools/with_venv.sh
always_venv=0
never_venv=0
just_pycodestyle=0
no_pycodestyle=0
just_pylint=0
integrated=0
force=0
noseargs=
wrapper=""
coverage=0
verbose=0

for arg in "$@"; do
  process_option $arg
done

# If enabled, tell nose to collect coverage data
if [ $coverage -eq 1 ]; then
    noseopts="$noseopts --with-coverage --cover-package=ryu"
fi

run_tests() {
  # Just run the test suites in current environment
  ${wrapper} rm -f ./$PLUGIN_DIR/tests.sqlite

  if [ $verbose -eq 1 ]; then
    ${wrapper} $NOSETESTS
  else
    ${wrapper} $NOSETESTS 2> run_tests.log
  fi
  # If we get some short import error right away, print the error log directly
  RESULT=$?
  if [ "$RESULT" -ne "0" ];
  then
    ERRSIZE=`wc -l run_tests.log | awk '{print \$1}'`
    if [ $verbose -eq 0 -a "$ERRSIZE" -lt "40" ];
    then
        cat run_tests.log
    fi
  fi
  return $RESULT
}

run_pylint() {
  echo "Running pylint ..."
  PYLINT_OPTIONS="--rcfile=.pylintrc --output-format=parseable"
  PYLINT_INCLUDE="ryu bin/ryu bin/ryu-manager ryu/tests/bin/ryu-client"
  export PYTHONPATH=$PYTHONPATH:.ryu
  PYLINT_LOG=pylint.log

  ${wrapper} pylint $PYLINT_OPTIONS $PYLINT_INCLUDE > $PYLINT_LOG
  #BASE_CMD="pylint $PYLINT_OPTIONS $PYLINT_INCLUDE > $PYLINT_LOG"
  #[ $verbose -eq 1 ] && $BASE_CMD || msg_count=`$BASE_CMD | grep 'ryu/' | wc -l`
  #if [ $verbose -eq 0 ]; then
  #  echo "Pylint messages count: " $msg_count
  #fi
  export PYTHONPATH=$OLD_PYTHONPATH
}

run_pycodestyle() {
  PYCODESTYLE=$(which pycodestyle || which pep8)
  if [ -z "${PYCODESTYLE}" ]
  then
    echo "Please install pycodestyle or pep8"
    return 1
  fi
  echo "Running $(basename ${PYCODESTYLE}) ..."

  PYCODESTYLE_OPTIONS="--repeat --show-source"
  PYCODESTYLE_INCLUDE="ryu setup*.py"
  PYCODESTYLE_LOG=pycodestyle.log
  ${wrapper} ${PYCODESTYLE} $PYCODESTYLE_OPTIONS $PYCODESTYLE_INCLUDE | tee $PYCODESTYLE_LOG
}

run_integrated() {
  echo "Running integrated test ..."

  INTEGRATED_TEST_RUNNER="./ryu/tests/integrated/run_tests_with_ovs12.py"
  sudo PYTHONPATH=. nosetests -s $INTEGRATED_TEST_RUNNER
}
#NOSETESTS="nosetests $noseopts $noseargs"
NOSETESTS="${PYTHON} ./ryu/tests/run_tests.py $noseopts $noseargs"

#if [ -n "$PLUGIN_DIR" ]
#then
#    if ! [ -f ./$PLUGIN_DIR/run_tests.py ]
#    then
#        echo "Could not find run_tests.py in plugin directory $PLUGIN_DIR"
#        exit 1
#    fi
#fi

if [ $never_venv -eq 0 ]
then
  # Remove the virtual environment if --force used
  if [ $force -eq 1 ]; then
    echo "Cleaning virtualenv..."
    rm -rf ${venv}
  fi
  if [ -e ${venv} ]; then
    wrapper="${with_venv}"
  else
    if [ $always_venv -eq 1 ]; then
      # Automatically install the virtualenv
      ${PYTHON} tools/install_venv.py
      wrapper="${with_venv}"
    else
      echo -e "No virtual environment found...create one? (Y/n) \c"
      read use_ve
      if [ "x$use_ve" = "xY" -o "x$use_ve" = "x" -o "x$use_ve" = "xy" ]; then
        # Install the virtualenv and run the test suite in it
        ${PYTHON} tools/install_venv.py
        wrapper=${with_venv}
      fi
    fi
  fi
fi

# Delete old coverage data from previous runs
if [ $coverage -eq 1 ]; then
    ${wrapper} coverage erase
fi

if [ $just_pycodestyle -eq 1 ]; then
    run_pycodestyle
    exit
fi
if [ $just_pylint -eq 1 ]; then
    run_pylint
    exit
fi

if [ $integrated -eq 1 ]; then
    run_integrated
    exit
fi

run_tests
RV=$?
if [ $no_pycodestyle -eq 0 ]; then
    run_pycodestyle
fi

if [ $coverage -eq 1 ]; then
    echo "Generating coverage report in coverage.xml and covhtml/"
    ${wrapper} coverage xml -i
    ${wrapper} coverage html -d covhtml -i
fi

exit $RV
