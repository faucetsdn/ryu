# Design : Mise à niveau Ryu vers Python 3.11 / 3.12

**Date :** 2026-05-14
**Dépôt :** olibrius/ryu4312 (fork de faucetsdn/ryu)
**Objectif :** Faire tourner Ryu sur Python 3.11 et 3.12, distribuer via GitHub Releases.

---

## Contexte

`faucetsdn/ryu` est figé depuis 2020 et déclaré compatible Python 3.5–3.9 seulement.
Python 3.12 supprime plusieurs modules stdlib (`distutils`, `imp`, `asyncore`) et
`eventlet==0.31.1` (pinnée dans le projet) est incompatible depuis Python 3.10+.
Le runner de tests utilise `nose`, abandonné et incompatible Python 3.10+.

---

## Périmètre

Trois phases livrées comme trois PRs indépendantes sur `olibrius/ryu4312`.

---

## Phase 1 — Fixes de compatibilité Python 3.11 / 3.12

**Branche :** `python3-compat-fixes`

### Dépendances

Fichier `tools/pip-requires` :

| Avant | Après | Raison |
|---|---|---|
| `eventlet==0.31.1` | `eventlet>=0.35.0` | 0.35+ supporte Python 3.11/3.12 |
| `packaging==20.9` | `packaging>=21.0` | dépinner, version moderne |
| `six>=1.4.0` | inchangé (phase 2) | encore utilisé massivement |

### Modules supprimés en Python 3.12 — 5 fichiers

| Fichier | Ligne | Avant | Après |
|---|---|---|---|
| `ryu/flags.py` | 20 | `from distutils.version import LooseVersion` | `from packaging.version import Version` + adapter usages `LooseVersion` → `Version` |
| `ryu/lib/packet/zebra.py` | 26 | `from distutils.version import LooseVersion` | même remplacement |
| `ryu/tests/unit/lib/ovs/test_vsctl.py` | 16 | `from distutils.spawn import find_executable` | `from shutil import which` |
| `ryu/tests/unit/cmd/test_manager.py` | 24 | `from imp import reload` | `from importlib import reload` |
| `ryu/tests/unit/ofproto/test_ofproto.py` | 21 | `from imp import reload` | même remplacement |

Note : `ryu/utils.py` utilise `imp` mais seulement sous `if six.PY2:` — jamais exécuté en Python 3, aucune modification requise.

### Infrastructure de tests

Remplacer `nose` par `pytest` (nose est incompatible Python 3.10+) :

- `tools/test-requires` : remplacer `nose` par `pytest`
- `ryu/tests/run_tests.py` : adapter pour pytest ou supprimer au profit d'un appel direct `pytest`
- `tox.ini` : mettre à jour `envlist` (py311, py312), commandes, et dépendances
- Remplacer `mock` standalone par `unittest.mock` (built-in Python 3.3+)

### Smoke tests

Ajouter `ryu/tests/unit/test_smoke.py` :
- Vérification que tous les packages principaux s'importent sans erreur
- `ryu-manager --version` via subprocess

### Mise à jour setup.cfg

- `python_requires = >=3.11` (prépare phase 3, valide dès phase 1)
- Retirer les classifiers Python 2.x, 3.5–3.10
- Ajouter classifiers Python 3.11, 3.12

---

## Phase 2 — Suppression de `six`

**Branche :** `remove-six` (basée sur `python3-compat-fixes`)

### Périmètre

53 fichiers non-test, 284 occurrences. Tous les remplacements sont mécaniques :

| Pattern `six` | Remplacement Python 3 natif |
|---|---|
| `six.binary_type` (158×) | `bytes` |
| `@six.add_metaclass(X)` (53×) | `class Foo(..., metaclass=X):` |
| `six.text_type` (23×) | `str` |
| `six.integer_types` (10×) | `int` |
| `six.string_types` (8×) | `str` |
| `six.PY3` guard (8×) | supprimer la branche `else` Python 2 |
| `six.int2byte(x)` (7×) | `bytes([x])` |
| `six.moves.*` (4×) | import direct équivalent |
| `six.indexbytes(b, i)` (3×) | `b[i]` |
| `six.next(it)` (2×) | `next(it)` |
| `six.StringIO` (1×) | `io.StringIO` |
| `six.PY2` guard (1×) | supprimer la branche entière |

Fin de phase : retirer `six>=1.4.0` de `tools/pip-requires`.

### Stratégie

Traiter les fichiers par groupe homogène (packet/, ofproto/, services/bgp/, etc.)
pour faciliter la revue. Un commit par groupe.

### Validation

La suite de tests (78 tests unitaires + smoke test) doit passer intégralement
sur Python 3.11 et 3.12 avant merge.

---

## Phase 3 — Packaging GitHub Releases

**Branche :** `packaging` (basée sur `remove-six`)

### setup.cfg

- `name = ryu4312`
- `version` géré par `pbr` (inchangé)
- `python_requires = >=3.11` (déjà posé en phase 1)
- Classifiers finaux : Python 3.11, 3.12

### tox.ini

Environnements finaux : `py311`, `py312`, `pycodestyle`.
Suppression des envs Python < 3.11.

### GitHub Actions — `.github/workflows/release.yml`

Déclenché sur push de tag `v*.*.*`.

```
Étapes :
1. Checkout
2. Matrix : Python 3.11 × 3.12
3. pip install build
4. python -m build  →  dist/*.whl + dist/*.tar.gz
5. Test d'installation depuis le wheel
6. Lancer la suite de tests (pytest)
7. github/create-release + upload des artefacts dist/
```

### GitHub Actions — `.github/workflows/ci.yml`

Déclenché sur push et pull_request vers master.
Matrix : Python 3.11 × 3.12.
Étapes : install deps → pytest → pycodestyle.

### Résultat attendu

Après un `git tag v4.35.0 && git push --tags`, les artefacts
`ryu4312-4.35.0-py3-none-any.whl` et `ryu4312-4.35.0.tar.gz`
sont disponibles dans la GitHub Release et installables via :

```bash
pip install https://github.com/olibrius/ryu4312/releases/download/v4.35.0/ryu4312-4.35.0-py3-none-any.whl
```

---

## Validation globale

| Phase | Signal de succès |
|---|---|
| 1 | `tox -e py311,py312` passe (78 tests + smoke) |
| 2 | même, plus aucun `import six` dans le code de production |
| 3 | GitHub Release créée avec les deux artefacts, installable sur Python 3.11 et 3.12 vierges |

---

## Ce qui n'est PAS dans le périmètre

- Tests d'intégration avec Mininet ou un vrai switch OpenFlow
- Migration vers `pyproject.toml` (hors scope, risque élevé)
- Support Python < 3.11 (volontairement abandonné)
- Publication PyPI (décision explicite : GitHub Releases uniquement)
