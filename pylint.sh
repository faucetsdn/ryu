#! /bin/sh

echo "Running pylint ..."
PYLINT_OPTIONS="--rcfile=pylintrc --output-format=parseable"
PYLINT_INCLUDE="ryu bin/ryu-manager bin/ryu-client"
export PYTHONPATH=$PYTHONPATH:.ryu
PYLINT_LOG=pylint.log

pylint $PYLINT_OPTIONS $PYLINT_INCLUDE > $PYLINT_LOG
