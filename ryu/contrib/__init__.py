# Adjust module loading path for third party libraries
import os
import sys

for path in __path__:
    if path in sys.path:
        sys.path.remove(path)
    path = os.path.abspath(path)
    if path in sys.path:
        sys.path.remove(path)
    sys.path.insert(0, path)  # prioritize our own copy than system's
