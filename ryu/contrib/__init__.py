import sys

_orig_sys_path = None

def update_module_path():
    # Adjust module loading path for third party libraries
    import os
    global _orig_sys_path

    _orig_sys_path = sys.path[:]
    for path in __path__:
        if path in sys.path:
            sys.path.remove(path)
        path = os.path.abspath(path)
        if path in sys.path:
            sys.path.remove(path)
        sys.path.insert(0, path)  # prioritize our own copy than system's

def restore_module_path():
    global _orig_sys_path

    sys.path = _orig_sys_path
    _orig_sys_path = None
