# Copyright (C) 2013,2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013,2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# this is a pyang plugin to generate ryu/lib/of_config/generated_classes.py
# usage example:
# PYTHONPATH=. ./bin/pyang --plugindir ~/git/ryu/tools/pyang_plugins -f ryu ~/git/ryu/tools/of-config1.1.1.yang > ~/git/ryu/lib/of_config/generated_classes.py


_COPYRIGHT_NOTICE = """
# Copyright (C) 2013,2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013,2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""


import sys
import StringIO
import pyang
from pyang import plugin


def pyang_plugin_init():
    plugin.register_plugin(RyuPlugin())


class RyuPlugin(plugin.PyangPlugin):
    def add_output_format(self, fmts):
        fmts['ryu'] = self

    def emit(self, ctx, modules, fd):
        emit_ryu(ctx, modules[0], fd)


def emit_ryu(ctx, module, fd):
    ctx.i_ryu_queue = []
    visit_children(ctx, module, fd, module.i_children)
    ctx.i_ryu_queue.reverse()
    generate_header(ctx)
    done = set()
    for s in ctx.i_ryu_queue:
        name = generate_type_name(s)
        if name in done:
            continue
        generate_class(s)
        done.add(name)


def visit_children(ctx, module, fd, children, prefix=''):
    for c in children:
        if not is_leaf(c):
            ctx.i_ryu_queue.append(c)
        if hasattr(c, 'i_children'):
            visit_children(ctx, module, fd, c.i_children, prefix + '  ')


def is_leaf(s):
    return s.keyword in ['leaf', 'leaf-list']


def generate_header(ctx):
    print _COPYRIGHT_NOTICE
    print '# do not edit.'
    print '# this file was mechanically generated with:'
    print '#    pyang %s' % pyang.__version__
    print '#    ryu.tools.pyang_plugins.ryu'
    for mod, ver in sorted(ctx.modules):
        print '#    %s@%s' % (mod, ver)
    print ''
    print 'from ryu.lib.of_config.base import _Base, _e, _ct'


def generate_class_def(s):
    try:
        return s.i_ryu_class_def
    except AttributeError:
        pass
    s.i_ryu_class_def = _generate_class_def(s)
    return s.i_ryu_class_def


def _generate_class_def(s):
    if is_leaf(s):
        return generate_type_name(s)
    o = StringIO.StringIO()
    print >> o, 'class %s(_Base):' % (generate_type_name(s),)
    print >> o, '    _ELEMENTS = ['
    for c in s.i_children:
        if is_leaf(c):
            print >> o, '        _e(\'%s\', is_list=%s),  # %s' % \
                (c.arg, c.keyword == 'leaf-list', generate_type_name(c),)
        else:
            print >> o, '        _ct(\'%s\',' % (c.arg,)
            print >> o, '            %s,' % (generate_type_name(c),)
            print >> o, '            is_list=%s),' % (c.keyword == 'list',)
    print >> o, '    ]'
    return o.getvalue()


def generate_class(s):
    print ''
    print ''
    sys.stdout.write(generate_class_def(s))


def same_class_def(s1, s2):
    return generate_class_def(s1) == generate_class_def(s2)


# 'hoge-hoge' -> 'HogeHoge'
def pythonify(name):
    a = name.split('-')
    a = map(lambda x: x.capitalize(), a)  # XXX locale sensitive
    return ''.join(a)


def chop_suf(s, suf):
    if not s.endswith(suf):
        return s
    return s[:-len(suf)]


_classes = {}


def generate_type_name(s):
    try:
        return s.i_ryu_class_name
    except AttributeError:
        pass
    s.i_ryu_class_name = name = _generate_type_name(s)
    assert (name not in _classes) or same_class_def(_classes[name], s)
    _classes[name] = s
    return name


def _generate_type_name(s):
    # 1. use the hardcoded name for the top level capable-switch.
    if s.arg == 'capable-switch':
        return 'OFCapableSwitchType'
    # 2. pick the name from the first yang grouping.
    # this relies on the way OF-Config yang specification is written.
    t = s.search_one('uses')
    if t:
        return t.arg
    # 3. pick the name of yang type.
    t = s.search_one('type')
    if t:
        return t.arg
    # 4. infer from the parent's name.
    # if the parent is 'OFFooType' and our name is 'bar-baz',
    # use 'OFFooBarBazType'.
    # again, this relies on the way OF-Config yang specification is written.
    return (chop_suf(generate_type_name(s.parent), 'Type')
            + pythonify(s.arg)
            + 'Type')
