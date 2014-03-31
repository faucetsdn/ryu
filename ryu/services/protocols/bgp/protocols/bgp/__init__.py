try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

# Pointer to active/available OrderedDict.
OrderedDict = OrderedDict
