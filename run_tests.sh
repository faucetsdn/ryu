#!/bin/sh

usage() {
  echo "Usage: $0 [OPTION]..."
  echo "Run Ryu's test suite(s)"
  echo ""
  echo "  -V, --virtual-env        Always use virtualenv.  Install automatically if not present"
  echo "  -N, --no-virtual-env     Don't use virtualenv.  Run tests in local environment"
  echo "  -c, --coverage           Generate coverage report"
  echo "  -f, --force              Force a clean re-build of the virtual environment. Useful when dependencies have been added."
  echo "  -p, --pep8               Just run pep8"
  echo "  -P, --no-pep8            Don't run pep8"
  echo "  -l, --pylint             Just run pylint"
  echo "  -v, --verbose            Run verbose pylint analysis"
  echo "  -h, --help               Print this usage message"
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
    -p|--pep8) just_pep8=1; never_venv=1; always_venv=0;;
    -P|--no-pep8) no_pep8=1;;
    -l|--pylint) just_pylint=1;;
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
just_pep8=0
no_pep8=0
just_pylint=0
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
  PYLINT_INCLUDE="ryu bin/ryu-manager bin/ryu-client"
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

run_pep8() {
  echo "Running pep8 ..."

  PEP8_EXCLUDE="vcsversion.py,*.pyc,contrib"
  PEP8_OPTIONS="--exclude=$PEP8_EXCLUDE --repeat --show-source"
  PEP8_INCLUDE="bin/* ryu setup*.py"
  PEP8_LOG=pep8.log
  ${wrapper} pep8 $PEP8_OPTIONS $PEP8_INCLUDE | tee $PEP8_LOG
}

#NOSETESTS="nosetests $noseopts $noseargs"
NOSETESTS="python ./ryu/tests/run_tests.py $noseopts $noseargs"

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
      python tools/install_venv.py
      wrapper="${with_venv}"
    else
      echo -e "No virtual environment found...create one? (Y/n) \c"
      read use_ve
      if [ "x$use_ve" = "xY" -o "x$use_ve" = "x" -o "x$use_ve" = "xy" ]; then
        # Install the virtualenv and run the test suite in it
        python tools/install_venv.py
        wrapper=${with_venv}
      fi
    fi
  fi
fi

# Delete old coverage data from previous runs
if [ $coverage -eq 1 ]; then
    ${wrapper} coverage erase
fi

if [ $just_pep8 -eq 1 ]; then
    run_pep8
    exit
fi
if [ $just_pylint -eq 1 ]; then
    run_pylint
    exit
fi

run_tests
RV=$?
if [ $no_pep8 -eq 0 ]; then
    run_pep8
fi

if [ $coverage -eq 1 ]; then
    echo "Generating coverage report in coverage.xml and covhtml/"
    ${wrapper} coverage xml -i
    ${wrapper} coverage html -d covhtml -i
fi

exit $RV
