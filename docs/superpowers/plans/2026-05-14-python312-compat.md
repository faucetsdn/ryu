# Python 3.11/3.12 Compatibility — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Faire tourner `olibrius/ryu4312` sur Python 3.11 et 3.12, puis distribuer via GitHub Releases.

**Architecture:** Trois PRs indépendantes sur des branches séquentielles. Phase 1 corrige les cassures stdlib (distutils, imp) et remplace le runner nose→pytest. Phase 2 supprime la dépendance `six`. Phase 3 ajoute le packaging GitHub Releases via Actions.

**Tech Stack:** Python 3.11/3.12, pytest, eventlet ≥ 0.35.0, packaging, GitHub Actions, `build` (PEP 517)

---

## ─── PHASE 1 — `python3-compat-fixes` ───

### Task 1 : Créer la branche et vérifier l'état de départ

**Files:**
- Aucun fichier modifié — vérification seulement

- [ ] **Créer la branche**

```bash
cd /mnt/d/ryu4312/ryu
git checkout -b python3-compat-fixes
```

- [ ] **Vérifier que Python 3.12 est bien disponible**

```bash
python3.12 --version || python3.11 --version
```

Attendu : `Python 3.12.x` ou `Python 3.11.x`

- [ ] **Installer les dépendances actuelles et constater les erreurs**

```bash
python3.12 -m pip install -e . 2>&1 | grep -E "error|Error|WARNING" | head -20
python3.12 -c "from ryu.flags import CONF" 2>&1
python3.12 -c "from distutils.version import LooseVersion" 2>&1
```

Attendu pour la dernière commande : `ModuleNotFoundError: No module named 'distutils'`

---

### Task 2 : Corriger `from imp import reload` (2 fichiers de test)

**Files:**
- Modify: `ryu/tests/unit/cmd/test_manager.py:17-27`
- Modify: `ryu/tests/unit/ofproto/test_ofproto.py:17-26`

- [ ] **Éditer `ryu/tests/unit/cmd/test_manager.py`**

Remplacer les lignes 17-25 :
```python
import sys
import unittest
import mock
from nose.tools import eq_, raises
```
par :
```python
import sys
import unittest
from unittest import mock
import pytest
from importlib import reload
```

Supprimer aussi ce bloc qui ne sert plus :
```python
try:
    # Python 3
    from imp import reload
except ImportError:
    # Python 2
    pass
```

- [ ] **Éditer `ryu/tests/unit/ofproto/test_ofproto.py`**

Remplacer le bloc lignes 17-27 :
```python
try:
    # Python 3
    from imp import reload
except ImportError:
    # Python 2
    pass

import unittest
import logging
from nose.tools import eq_
```
par :
```python
import unittest
import logging
from importlib import reload
```

- [ ] **Vérifier les imports**

```bash
python3.12 -c "import ryu.tests.unit.cmd.test_manager" 2>&1
python3.12 -c "import ryu.tests.unit.ofproto.test_ofproto" 2>&1
```

Attendu : aucune sortie (pas d'erreur)

- [ ] **Commit**

```bash
git add ryu/tests/unit/cmd/test_manager.py ryu/tests/unit/ofproto/test_ofproto.py
git commit -m "fix: replace imp.reload with importlib.reload (removed in Python 3.12)"
```

---

### Task 3 : Corriger `distutils.version.LooseVersion` dans le code source (2 fichiers)

**Files:**
- Modify: `ryu/flags.py:20` et `ryu/flags.py:90-95`
- Modify: `ryu/lib/packet/zebra.py:26`

- [ ] **Éditer `ryu/flags.py`**

Ligne 20 — remplacer :
```python
from distutils.version import LooseVersion
```
par :
```python
from packaging.version import Version as LooseVersion
```

Lignes 90-95 — supprimer le hack Python 2 devenu inutile :
```python
# Hack: In oslo_config.cfg.Opt, ConfigType might access __class__ attribute
# for equal comparison, but on Python 2, LooseVersion does not have __class__
# attribute and it causes AttributeError. So here inject __class__ attribute
# into LooseVersion class.
if not hasattr(LooseVersion, '__class__'):
    LooseVersion.__class__ = LooseVersion
```
(supprimer ces 6 lignes entièrement)

- [ ] **Éditer `ryu/lib/packet/zebra.py`**

Ligne 26 — remplacer :
```python
from distutils.version import LooseVersion
```
par :
```python
from packaging.version import Version as LooseVersion
```

- [ ] **Vérifier**

```bash
python3.12 -c "from ryu import flags" 2>&1
python3.12 -c "from ryu.lib.packet import zebra" 2>&1
```

Attendu : aucune erreur

- [ ] **Commit**

```bash
git add ryu/flags.py ryu/lib/packet/zebra.py
git commit -m "fix: replace distutils.version.LooseVersion with packaging.version.Version"
```

---

### Task 4 : Corriger `distutils.spawn.find_executable` dans le test ovs

**Files:**
- Modify: `ryu/tests/unit/lib/ovs/test_vsctl.py:16`

- [ ] **Éditer `ryu/tests/unit/lib/ovs/test_vsctl.py`**

Remplacer la ligne 16 :
```python
from distutils.spawn import find_executable
```
par :
```python
from shutil import which as find_executable
```

Remplacer aussi les lignes 19-22 (imports nose) :
```python
from nose.tools import eq_
from nose.tools import ok_
```
par rien (ces deux lignes seront retirées — `eq_` et `ok_` seront remplacés à la Task 7).

Note : ne pas supprimer les appels à `eq_`/`ok_` maintenant, seulement les imports — la Task 7 s'en charge.

- [ ] **Commit**

```bash
git add ryu/tests/unit/lib/ovs/test_vsctl.py
git commit -m "fix: replace distutils.spawn.find_executable with shutil.which"
```

---

### Task 5 : Mettre à jour les dépendances

**Files:**
- Modify: `tools/pip-requires`

- [ ] **Éditer `tools/pip-requires`**

Remplacer :
```
eventlet==0.31.1
```
par :
```
eventlet>=0.35.0
```

Remplacer :
```
packaging==20.9
```
par :
```
packaging>=21.0
```

- [ ] **Vérifier l'installation avec les nouvelles dépendances**

```bash
python3.12 -m pip install -r tools/pip-requires 2>&1 | tail -5
```

Attendu : `Successfully installed eventlet-0.3x.x ...`

- [ ] **Commit**

```bash
git add tools/pip-requires
git commit -m "fix: upgrade eventlet>=0.35.0 for Python 3.11/3.12 support, unpin packaging"
```

---

### Task 6 : Remplacer le runner nose par pytest

**Files:**
- Modify: `tools/test-requires`
- Modify: `tox.ini`
- Modify: `ryu/tests/run_tests.py`

- [ ] **Éditer `tools/test-requires`**

Remplacer le contenu entier par :
```
pytest
pytest-cov
coverage
pycodestyle
autopep8
formencode
```

(Supprimer : `nose`, `mock`, `pylint`, `pytype` — mock est dans stdlib, pylint/pytype sont optionnels)

- [ ] **Remplacer `ryu/tests/run_tests.py`**

Remplacer le contenu entier par :
```python
#!/usr/bin/env python
"""Test runner — delegated to pytest."""
import sys
import pytest

if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] or ['ryu/tests/unit']))
```

- [ ] **Remplacer `tox.ini`**

Remplacer le contenu entier par :
```ini
[tox]
envlist = py311,py312,pycodestyle

[gh-actions]
python =
  3.11: py311
  3.12: py312

[testenv]
deps =
  -U
  -r{toxinidir}/tools/pip-requires
  --no-cache-dir
usedevelop = True
commands =
  pip install -r{toxinidir}/tools/test-requires
  ryu-manager ryu/tests/unit/cmd/dummy_openflow_app.py
  pytest {posargs:ryu/tests/unit} -v --tb=short

[testenv:pycodestyle]
deps =
  pycodestyle
commands =
  pycodestyle ryu/

[pycodestyle]
exclude = pbr-*,.venv,.tox,.git,doc,dist,tools,vcsversion.py,.pyc,ryu/contrib
ignore = W503,W504,E116,E402,E501,E722,E731,E741
```

- [ ] **Vérifier que pytest trouve les tests**

```bash
python3.12 -m pytest ryu/tests/unit --collect-only 2>&1 | tail -10
```

Attendu : liste de tests collectés, pas d'erreur fatale

- [ ] **Commit**

```bash
git add tools/test-requires ryu/tests/run_tests.py tox.ini
git commit -m "test: replace nose runner with pytest, update tox.ini for py311/py312"
```

---

### Task 7 : Remplacer `nose.tools.eq_` et `ok_` dans les 72 fichiers de test

**Files:**
- Modify: tous les `ryu/tests/unit/**/*.py` qui importent nose.tools

- [ ] **Remplacement en masse des imports `eq_` / `ok_` / `raises` / `nottest`**

```bash
cd /mnt/d/ryu4312/ryu

# Supprimer les lignes d'import nose.tools simples
find ryu/tests/unit -name "*.py" -exec sed -i \
  -e '/^from nose\.tools import eq_$/d' \
  -e '/^from nose\.tools import ok_$/d' \
  -e '/^from nose import .*$/d' \
  {} +

# Remplacer les imports multi-symboles courants (les plus fréquents)
find ryu/tests/unit -name "*.py" -exec sed -i \
  -e 's/from nose\.tools import ok_, eq_$/pass  # nose removed/g' \
  -e 's/from nose\.tools import eq_, ok_$/pass  # nose removed/g' \
  -e 's/from nose\.tools import ok_, eq_, raises$/import pytest/g' \
  -e 's/from nose\.tools import ok_, eq_, raises, nottest$/import pytest/g' \
  -e 's/from nose\.tools import ok_, eq_, nottest$/import pytest/g' \
  -e 's/from nose\.tools import eq_, raises$/import pytest/g' \
  -e 's/from nose\.tools import eq_, ok_, raises$/import pytest/g' \
  -e 's/from nose\.tools import raises$/import pytest/g' \
  -e 's/from nose\.tools import \*$/import pytest/g' \
  {} +
```

- [ ] **Remplacer les appels `eq_(a, b)` → `assert a == b`**

```bash
# eq_(a, b) → assert a == b   (forme la plus commune)
find ryu/tests/unit -name "*.py" -exec python3 -c "
import re, sys
path = sys.argv[1]
content = open(path).read()
# eq_(a, b) avec indentation
new = re.sub(r'(\s+)eq_\((.+?),\s*(.+?)\)\s*$',
             lambda m: m.group(1) + 'assert ' + m.group(2).strip() + ' == ' + m.group(3).strip(),
             content, flags=re.MULTILINE)
if new != content:
    open(path, 'w').write(new)
" {} \;
```

- [ ] **Remplacer `ok_(x)` → `assert x`**

```bash
find ryu/tests/unit -name "*.py" -exec python3 -c "
import re, sys
path = sys.argv[1]
content = open(path).read()
new = re.sub(r'(\s+)ok_\((.+?)\)\s*$',
             lambda m: m.group(1) + 'assert ' + m.group(2).strip(),
             content, flags=re.MULTILINE)
if new != content:
    open(path, 'w').write(new)
" {} \;
```

- [ ] **Remplacer `@nottest` → `@pytest.mark.skip`**

```bash
find ryu/tests/unit -name "*.py" -exec sed -i \
  's/@nottest/@pytest.mark.skip(reason="marked nottest")/g' {} +
```

- [ ] **Nettoyer les lignes `pass  # nose removed` parasites**

```bash
find ryu/tests/unit -name "*.py" -exec sed -i '/^pass  # nose removed$/d' {} +
```

- [ ] **Vérifier qu'il ne reste plus d'imports nose.tools**

```bash
grep -rn "from nose" ryu/tests/unit --include="*.py"
```

Attendu : aucune ligne (sauf éventuellement des import mock — traités Task 8)

- [ ] **Commit**

```bash
git add ryu/tests/unit/
git commit -m "test: replace nose.tools (eq_, ok_, nottest) with native pytest/assert"
```

---

### Task 8 : Convertir `@raises(Exc)` → `pytest.raises` (27 fichiers)

**Files:**
- Modify: tous les fichiers avec `@raises(` dans `ryu/tests/unit/`

Le pattern nose `@raises(Exc)` décore une méthode entière. En pytest, on l'encapsule dans un `with pytest.raises(Exc):`.

- [ ] **Script de conversion automatique**

```bash
python3 - <<'PYEOF'
import re, os, glob

pattern = re.compile(
    r'(\s+)@raises\(([^)]+)\)\n(\s+)(def test_\w+\(self[^)]*\):)\n((?:\s+.+\n)+)',
    re.MULTILINE
)

def convert(m):
    indent = m.group(1)
    exc = m.group(2)
    fn_indent = m.group(3)
    fn_sig = m.group(4)
    body = m.group(5)
    # Indent body one level deeper (4 spaces)
    new_body = re.sub(r'^(\s+)', r'    \1', body, flags=re.MULTILINE)
    return (f"{fn_indent}{fn_sig}\n"
            f"{fn_indent}    with pytest.raises({exc}):\n"
            f"{new_body}")

for path in glob.glob('ryu/tests/unit/**/*.py', recursive=True):
    content = open(path).read()
    new = pattern.sub(convert, content)
    if new != content:
        open(path, 'w').write(new)
        print(f"Converted: {path}")
PYEOF
```

- [ ] **Vérifier les conversions sur un fichier clé**

```bash
grep -A6 "def test_version" ryu/tests/unit/cmd/test_manager.py
```

Attendu :
```python
def test_version(self):
    with pytest.raises(SystemExit):
        main()
```

- [ ] **Vérifier qu'il ne reste plus de `@raises(`**

```bash
grep -rn "@raises(" ryu/tests/unit --include="*.py"
```

Attendu : aucune ligne

- [ ] **Commit**

```bash
git add ryu/tests/unit/
git commit -m "test: convert @raises(Exc) decorators to pytest.raises context managers"
```

---

### Task 9 : Remplacer `import mock` standalone par `unittest.mock`

**Files:**
- Modify: `ryu/tests/unit/app/test_ws_topology.py:21`
- Modify: `ryu/tests/unit/cmd/test_manager.py` (déjà fait Task 2)

- [ ] **Remplacement en masse**

```bash
find ryu/tests/unit -name "*.py" -exec sed -i \
  -e 's/^import mock$/from unittest import mock/g' \
  -e '/^try:$/,/^    from unittest import mock.*Python 3.*$/d' \
  {} +

# Nettoyer les patterns try/except mock legacy
find ryu/tests/unit -name "*.py" -exec python3 -c "
import re, sys
path = sys.argv[1]
content = open(path).read()
# Remove try: import mock / except: from unittest import mock patterns
new = re.sub(
    r'try:\s*\n\s+import mock\s*#.*\n\s*except ImportError:\s*\n\s+from unittest import mock.*\n',
    'from unittest import mock\n',
    content
)
if new != content:
    open(path, 'w').write(new)
" {} \;
```

- [ ] **Vérifier**

```bash
grep -rn "^import mock$" ryu/tests/unit --include="*.py"
```

Attendu : aucune ligne

- [ ] **Commit**

```bash
git add ryu/tests/unit/
git commit -m "test: replace standalone mock with unittest.mock (built-in since Python 3.3)"
```

---

### Task 10 : Ajouter le smoke test

**Files:**
- Create: `ryu/tests/unit/test_smoke.py`

- [ ] **Créer `ryu/tests/unit/test_smoke.py`**

```python
"""Smoke tests — vérifient que tous les modules principaux s'importent sans erreur."""
import subprocess
import sys
import pytest


CORE_MODULES = [
    'ryu',
    'ryu.base.app_manager',
    'ryu.controller.controller',
    'ryu.lib.hub',
    'ryu.lib.packet.packet',
    'ryu.lib.packet.ethernet',
    'ryu.lib.packet.ipv4',
    'ryu.lib.packet.ipv6',
    'ryu.lib.packet.tcp',
    'ryu.lib.packet.udp',
    'ryu.lib.packet.bgp',
    'ryu.lib.packet.zebra',
    'ryu.ofproto.ofproto_v1_3_parser',
    'ryu.ofproto.ofproto_v1_4_parser',
    'ryu.ofproto.ofproto_v1_5_parser',
    'ryu.flags',
    'ryu.app.wsgi',
]


@pytest.mark.parametrize('module', CORE_MODULES)
def test_module_importable(module):
    result = subprocess.run(
        [sys.executable, '-c', f'import {module}'],
        capture_output=True, text=True
    )
    assert result.returncode == 0, (
        f"Cannot import {module}:\n{result.stderr}"
    )


def test_ryu_manager_version():
    result = subprocess.run(
        [sys.executable, '-m', 'ryu.cmd.manager', '--version'],
        capture_output=True, text=True
    )
    assert result.returncode == 0 or 'ryu' in result.stdout.lower() or 'ryu' in result.stderr.lower(), (
        f"ryu-manager --version failed:\n{result.stderr}"
    )
```

- [ ] **Lancer le smoke test**

```bash
python3.12 -m pytest ryu/tests/unit/test_smoke.py -v 2>&1
```

Attendu : tous les `test_module_importable` passent

- [ ] **Commit**

```bash
git add ryu/tests/unit/test_smoke.py
git commit -m "test: add smoke tests for core module imports and ryu-manager startup"
```

---

### Task 11 : Mettre à jour setup.cfg et lancer la suite complète

**Files:**
- Modify: `setup.cfg`

- [ ] **Éditer `setup.cfg`** — section `[metadata]`

Remplacer les classifiers Python existants :
```ini
    Programming Language :: Python :: 3.5
    Programming Language :: Python :: 3.6
    Programming Language :: Python :: 3.7
    Programming Language :: Python :: 3.8
    Programming Language :: Python :: 3.9
```
par :
```ini
    Programming Language :: Python :: 3.11
    Programming Language :: Python :: 3.12
```

Ajouter après la section `[files]` :
```ini
[options]
python_requires = >=3.11
```

- [ ] **Lancer la suite complète de tests**

```bash
python3.12 -m pip install -e . -r tools/pip-requires
python3.12 -m pip install -r tools/test-requires
python3.12 -m pytest ryu/tests/unit -v --tb=short 2>&1 | tail -30
```

Attendu : `X passed, Y warnings` — tous les tests passent

- [ ] **Commit final de phase 1**

```bash
git add setup.cfg
git commit -m "build: set python_requires>=3.11, update classifiers for 3.11/3.12"
```

- [ ] **Pousser la branche et ouvrir la PR**

```bash
source /mnt/d/ryu4312/me.info
git push https://olibrius:${PAT}@github.com/olibrius/ryu4312.git python3-compat-fixes
```

Ouvrir la PR sur GitHub : `python3-compat-fixes` → `master`

---

## ─── PHASE 2 — `remove-six` ───

### Task 12 : Créer la branche de travail

**Files:** aucun

- [ ] **Créer la branche depuis la fin de Phase 1**

```bash
git checkout master
git merge python3-compat-fixes  # ou partir après merge de la PR
git checkout -b remove-six
```

- [ ] **Inventaire précis avant de commencer**

```bash
grep -rn "import six\|from six" ryu/ --include="*.py" | grep -v "/tests/" | wc -l
```

Attendu : 54 lignes environ

---

### Task 13 : Supprimer `six` dans `ryu/lib/packet/` (23 fichiers)

**Files:**
- Modify: tous les `ryu/lib/packet/*.py` qui importent six

Pattern principal dans ce répertoire : `six.binary_type` (158 occurrences au total dans le projet, dont ~80 dans packet/).

- [ ] **Remplacements mécaniques dans ryu/lib/packet/**

```bash
find ryu/lib/packet -name "*.py" -exec sed -i \
  -e 's/six\.binary_type/bytes/g' \
  -e 's/six\.text_type/str/g' \
  -e 's/six\.integer_types/(int,)/g' \
  -e 's/six\.string_types/str/g' \
  -e 's/six\.int2byte(\([^)]*\))/bytes([\1])/g' \
  -e 's/six\.indexbytes(\([^,]*\),\s*\([^)]*\))/\1[\2]/g' \
  -e 's/six\.next(\([^)]*\))/next(\1)/g' \
  {} +
```

- [ ] **Traiter `@six.add_metaclass(abc.ABCMeta)` dans packet_base.py**

Fichier `ryu/lib/packet/packet_base.py` — remplacer :
```python
import six
...
@six.add_metaclass(abc.ABCMeta)
class PacketBase(stringify.StringifyMixin):
```
par :
```python
class PacketBase(stringify.StringifyMixin, metaclass=abc.ABCMeta):
```
(et supprimer `import six`)

- [ ] **Script pour tous les `@six.add_metaclass` dans packet/**

```bash
python3 - <<'PYEOF'
import re, glob

pat = re.compile(
    r'@six\.add_metaclass\(([^)]+)\)\s*\nclass (\w+)\(([^)]*)\):',
    re.MULTILINE
)

for path in glob.glob('ryu/lib/packet/*.py'):
    content = open(path).read()
    new = pat.sub(lambda m: f'class {m.group(2)}({m.group(3)}, metaclass={m.group(1)}):', content)
    if new != content:
        open(path, 'w').write(new)
        print(f"Converted metaclass in {path}")
PYEOF
```

- [ ] **Supprimer les `import six` et `from six import` devenus inutiles dans packet/**

```bash
find ryu/lib/packet -name "*.py" -exec sed -i \
  -e '/^import six$/d' \
  -e '/^from six import /d' \
  {} +
```

- [ ] **Vérifier qu'il ne reste plus de `six` dans packet/**

```bash
grep -rn "six" ryu/lib/packet/ --include="*.py"
```

Attendu : aucune ligne

- [ ] **Lancer les tests packet**

```bash
python3.12 -m pytest ryu/tests/unit/packet/ -v --tb=short 2>&1 | tail -20
```

Attendu : tous les tests passent

- [ ] **Commit**

```bash
git add ryu/lib/packet/
git commit -m "refactor: remove six dependency from ryu/lib/packet/"
```

---

### Task 14 : Supprimer `six` dans `ryu/ofproto/` (6 fichiers)

**Files:**
- Modify: `ryu/ofproto/ofproto_parser.py`, `nx_actions.py`, `ofproto_v1_0_parser.py`, `ofproto_v1_2_parser.py`, `ofproto_v1_3_parser.py`, `ofproto_v1_4_parser.py`, `ofproto_v1_5_parser.py`, `oxx_fields.py`

- [ ] **Remplacements mécaniques dans ryu/ofproto/**

```bash
find ryu/ofproto -name "*.py" -exec sed -i \
  -e 's/six\.binary_type/bytes/g' \
  -e 's/six\.text_type/str/g' \
  -e 's/six\.integer_types/(int,)/g' \
  -e 's/six\.string_types/str/g' \
  -e 's/six\.int2byte(\([^)]*\))/bytes([\1])/g' \
  -e 's/six\.PY3/True/g' \
  {} +
```

- [ ] **Traiter les `@six.add_metaclass` dans ofproto/**

```bash
python3 - <<'PYEOF'
import re, glob

pat = re.compile(
    r'@six\.add_metaclass\(([^)]+)\)\s*\nclass (\w+)\(([^)]*)\):',
    re.MULTILINE
)

for path in glob.glob('ryu/ofproto/*.py'):
    content = open(path).read()
    new = pat.sub(lambda m: f'class {m.group(2)}({m.group(3)}, metaclass={m.group(1)}):', content)
    if new != content:
        open(path, 'w').write(new)
        print(f"Converted: {path}")
PYEOF
```

- [ ] **Traiter les blocs `if six.PY3:` / `else:` (supprimer la branche PY2)**

```bash
python3 - <<'PYEOF'
import re, glob

# Remove: if six.PY3:\n    <block>\nelse:\n    <py2-block>
# Keep only the PY3 block
pat = re.compile(
    r'if six\.PY3:(.*?)else:.*?(?=\n\S|\Z)',
    re.DOTALL | re.MULTILINE
)

for path in glob.glob('ryu/ofproto/*.py'):
    content = open(path).read()
    new = pat.sub(lambda m: m.group(1).strip(), content)
    if new != content:
        open(path, 'w').write(new)
        print(f"Simplified PY3 guard in {path}")
PYEOF
```

- [ ] **Supprimer les imports `six` dans ofproto/**

```bash
find ryu/ofproto -name "*.py" -exec sed -i '/^import six$/d' {} +
```

- [ ] **Vérifier**

```bash
grep -rn "six" ryu/ofproto/ --include="*.py"
python3.12 -m pytest ryu/tests/unit/ofproto/ -v --tb=short 2>&1 | tail -20
```

- [ ] **Commit**

```bash
git add ryu/ofproto/
git commit -m "refactor: remove six dependency from ryu/ofproto/"
```

---

### Task 15 : Supprimer `six` dans `ryu/services/protocols/bgp/` et les fichiers restants

**Files:**
- Modify: tous les fichiers `ryu/services/protocols/bgp/**/*.py` qui importent six
- Modify: `ryu/lib/stringify.py`, `ryu/lib/type_desc.py`, `ryu/lib/rpc.py`, `ryu/lib/mac.py`, etc.
- Modify: `ryu/app/wsgi.py`, `ryu/topology/switches.py`, `ryu/utils.py`

- [ ] **Corriger manuellement les 4 occurrences `six.moves` avant le sed en masse**

```python
# ryu/app/rest_conf_switch.py:26
# Remplacer :
from six.moves import http_client
# Par :
from http import client as http_client

# ryu/lib/stringify.py:41
# Remplacer :
_RESERVED_KEYWORD = dir(six.moves.builtins)
# Par :
import builtins
_RESERVED_KEYWORD = dir(builtins)

# ryu/lib/packet/bgp.py:55
# Remplacer :
reduce = six.moves.reduce
# Par :
from functools import reduce

# ryu/services/protocols/bgp/peer.py:24
# Remplacer :
from six.moves import zip_longest
# Par :
from itertools import zip_longest
```

- [ ] **Remplacements mécaniques — tous les fichiers restants**

```bash
find ryu/ -name "*.py" -not -path "*/tests/*" -exec sed -i \
  -e 's/six\.binary_type/bytes/g' \
  -e 's/six\.text_type/str/g' \
  -e 's/six\.integer_types/(int,)/g' \
  -e 's/six\.string_types/str/g' \
  -e 's/six\.int2byte(\([^)]*\))/bytes([\1])/g' \
  -e 's/six\.indexbytes(\([^,]*\),\s*\([^)]*\))/\1[\2]/g' \
  -e 's/six\.next(\([^)]*\))/next(\1)/g' \
  -e 's/six\.StringIO/io.StringIO/g' \
  -e 's/six\.PY3/True/g' \
  -e 's/six\.PY2/False/g' \
  {} +
```

- [ ] **Traiter les `@six.add_metaclass` restants**

```bash
python3 - <<'PYEOF'
import re, glob, os

pat = re.compile(
    r'@six\.add_metaclass\(([^)]+)\)\s*\nclass (\w+)\(([^)]*)\):',
    re.MULTILINE
)

for root, dirs, files in os.walk('ryu/'):
    dirs[:] = [d for d in dirs if d != 'tests']
    for fname in files:
        if not fname.endswith('.py'):
            continue
        path = os.path.join(root, fname)
        content = open(path).read()
        new = pat.sub(lambda m: f'class {m.group(2)}({m.group(3)}, metaclass={m.group(1)}):', content)
        if new != content:
            open(path, 'w').write(new)
            print(f"Converted: {path}")
PYEOF
```

- [ ] **Nettoyer `ryu/utils.py` — supprimer la branche `six.PY2`**

La fonction `load_source` dans `ryu/utils.py` contient :
```python
if six.PY2:
    import imp
    return imp.load_source(name, pathname)
else:
    loader = importlib.machinery.SourceFileLoader(name, pathname)
    return loader.load_module(name)
```

Remplacer par :
```python
loader = importlib.machinery.SourceFileLoader(name, pathname)
spec = importlib.util.spec_from_file_location(name, pathname, loader=loader)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
return module
```

(Ceci corrige aussi la dépréciation de `load_module()`)

- [ ] **Vérifier l'ajout de `import io` là où `six.StringIO` est remplacé**

```bash
grep -rn "io\.StringIO" ryu/ --include="*.py" | grep -v "^import io" | while read line; do
    file=$(echo $line | cut -d: -f1)
    grep -q "^import io" $file || echo "MISSING import io in $file"
done
```

Ajouter `import io` manuellement dans les fichiers signalés.

- [ ] **Supprimer tous les imports `six` restants**

```bash
find ryu/ -name "*.py" -not -path "*/tests/*" -exec sed -i \
  -e '/^import six$/d' \
  -e '/^from six import /d' \
  -e '/^from six\. import /d' \
  {} +
```

- [ ] **Vérifier qu'il ne reste plus de `six` dans le code source**

```bash
grep -rn "six" ryu/ --include="*.py" --exclude-dir=tests
```

Attendu : aucune ligne

- [ ] **Lancer la suite complète**

```bash
python3.12 -m pytest ryu/tests/unit -v --tb=short 2>&1 | tail -30
```

Attendu : tous les tests passent

- [ ] **Retirer `six` des dépendances**

Dans `tools/pip-requires`, supprimer la ligne :
```
six>=1.4.0
```

- [ ] **Commit final de phase 2**

```bash
git add ryu/
git commit -m "refactor: remove six library, use native Python 3 types throughout"
```

- [ ] **Pousser et ouvrir la PR**

```bash
source /mnt/d/ryu4312/me.info
git push https://olibrius:${PAT}@github.com/olibrius/ryu4312.git remove-six
```

---

## ─── PHASE 3 — `packaging` ───

### Task 16 : Créer la branche et finaliser setup.cfg

**Files:**
- Modify: `setup.cfg`

- [ ] **Créer la branche**

```bash
git checkout -b packaging  # basée sur remove-six après merge PR
```

- [ ] **Éditer `setup.cfg`** — changer le nom du paquet et finaliser

```ini
[metadata]
name = ryu4312
summary = Ryu SDN Framework — fork Python 3.11/3.12 (olibrius/ryu4312)
license = Apache License 2.0
author = Ryu project team / olibrius
author-email = Olivier.Tirat@clouddataengine.io
home-page = https://github.com/olibrius/ryu4312
description-file = README.rst
platform = any
classifier =
    Development Status :: 5 - Production/Stable
    License :: OSI Approved :: Apache Software License
    Topic :: System :: Networking
    Natural Language :: English
    Programming Language :: Python
    Programming Language :: Python :: 3
    Programming Language :: Python :: 3.11
    Programming Language :: Python :: 3.12
    Operating System :: Unix

[options]
python_requires = >=3.11
```

- [ ] **Commit**

```bash
git add setup.cfg
git commit -m "build: rename package ryu4312, finalize metadata for Python 3.11/3.12"
```

---

### Task 17 : Créer le workflow CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Créer `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
    branches: ["master", "python3-compat-fixes", "remove-six", "packaging"]
  pull_request:
    branches: ["master"]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r tools/pip-requires
          pip install -r tools/test-requires
          pip install -e .

      - name: Run tests
        run: pytest ryu/tests/unit -v --tb=short

      - name: Smoke test
        run: python -c "import ryu; print('ryu imported OK')"
```

- [ ] **Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions CI workflow for Python 3.11 and 3.12"
```

---

### Task 18 : Créer le workflow Release

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Créer `.github/workflows/release.yml`**

```yaml
name: Release

on:
  push:
    tags:
      - "v*.*.*"

jobs:
  build-and-release:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip build
          pip install -r tools/pip-requires
          pip install -r tools/test-requires
          pip install -e .

      - name: Run tests
        run: pytest ryu/tests/unit -v --tb=short

  release:
    needs: build-and-release
    runs-on: ubuntu-latest

    permissions:
      contents: write

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python 3.12
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Build wheel and sdist
        run: |
          pip install build
          python -m build
          ls -la dist/

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          files: |
            dist/*.whl
            dist/*.tar.gz
          generate_release_notes: true
```

- [ ] **Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add GitHub Actions release workflow — builds wheel+sdist on tag push"
```

---

### Task 19 : Test end-to-end du packaging et push final

**Files:** aucun nouveau

- [ ] **Vérifier le build local**

```bash
pip install build
python -m build
ls -la dist/
```

Attendu : `dist/ryu4312-X.Y.Z-py3-none-any.whl` et `dist/ryu4312-X.Y.Z.tar.gz`

- [ ] **Tester l'installation depuis le wheel dans un venv vierge**

```bash
python3.12 -m venv /tmp/test-ryu4312
/tmp/test-ryu4312/bin/pip install dist/ryu4312-*.whl
/tmp/test-ryu4312/bin/python -c "import ryu; print('OK')"
/tmp/test-ryu4312/bin/ryu-manager --version
```

Attendu : `ryu X.Y.Z` affiché sans erreur

- [ ] **Pousser la branche et ouvrir la PR**

```bash
source /mnt/d/ryu4312/me.info
git push https://olibrius:${PAT}@github.com/olibrius/ryu4312.git packaging
```

- [ ] **Créer le premier tag après merge de la PR**

```bash
git tag v4.35.0
source /mnt/d/ryu4312/me.info
git push https://olibrius:${PAT}@github.com/olibrius/ryu4312.git v4.35.0
```

Aller sur `https://github.com/olibrius/ryu4312/releases` — vérifier que la Release est créée avec les artefacts `.whl` et `.tar.gz`.

---

## Récapitulatif des fichiers modifiés

| Phase | Fichiers créés | Fichiers modifiés |
|---|---|---|
| 1 | `ryu/tests/unit/test_smoke.py` | 7 fichiers source + 72 fichiers tests |
| 2 | — | 53 fichiers source |
| 3 | `.github/workflows/ci.yml`, `.github/workflows/release.yml` | `setup.cfg` |
