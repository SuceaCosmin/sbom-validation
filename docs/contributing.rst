Contributing to the requirements
================================

Traceability workflow
---------------------

Use these link options when adding artifacts:

* ``:references:`` links a requirement to the standard or source document it
  relies on.
* ``:derived_from:`` links a refined requirement to its parent requirement.
* ``:implements:`` and ``:verifies:`` link explicit ``impl`` and ``test`` needs.

Record source-derived requirements with stable IDs and exact source and
version citations. Set ``status``, ``origin``, ``level``, ``result_kind`` and
``release`` on every requirement, and ``section`` on requirements taken from a standard (see :doc:`reading-guide`).

Mark implementations and tests
------------------------------

Put a one-line comment next to the code or test that realises the requirement:

.. code-block:: python

   # @need-ids: REQ_BSI11_TIMESTAMP

The marker fills the requirement's **code_url** (from ``src/``) or
**test_url** (from ``tests/``). The ``tests/test_traceability.py`` check
fails if a BSI requirement has no marker in ``src/``.

Build and check
---------------

.. code-block:: console

   poetry install --with docs,test
   poetry run sphinx-build -W -b html docs docs/_build/html

``-W`` turns warnings into errors, so an unknown status, an unresolved link or
an invalid ID fails the build. CI runs the same command.

Configuration
-------------

Need types, links, statuses and custom fields are defined once, in
``ubproject.toml``. ``docs/conf.py`` reads that file, so ubCode and Sphinx
always agree; do not duplicate the settings in ``conf.py``.
