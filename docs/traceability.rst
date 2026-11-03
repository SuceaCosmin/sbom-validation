Traceability
============

Evidence that each requirement is implemented and tested. Implementation and
test evidence comes from ``# @need-ids:`` markers in ``src/`` and ``tests/``;
the **Evidence** column counts them. Expand a requirement card (the arrow in its
header) to follow the links to the marked lines, or download the CSV below for
the full list of code and test locations.

Traceability matrix
-------------------

.. include:: _includes/legend.rst

.. raw:: html

   <p><a href="matrix.csv" download>Download the matrix as CSV</a> (for audit and spreadsheets).</p>


.. needtable::
   :types: req
   :columns: id;title;section;status;evidence as "Evidence"
   :style: datatables

Gaps
----

No code evidence
~~~~~~~~~~~~~~~~

Requirements with no ``# @need-ids:`` marker in ``src/``. An empty table means
every requirement has code evidence. ``REQ_TRACE_002`` is a process
requirement that is met by tests and documentation tooling only.

.. needtable::
   :types: req
   :columns: id;title;status
   :filter: not code_url
   :style: table

No test evidence
~~~~~~~~~~~~~~~~

Requirements with no ``# @need-ids:`` marker in ``tests/``.

.. needtable::
   :types: req
   :columns: id;title;status
   :filter: not test_url
   :style: table

Status does not match evidence
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The documentation build checks every requirement and **fails** (``-W``) when its
``status`` disagrees with its evidence: ``draft`` and ``approved`` must have no
markers, ``implemented`` needs a code marker and no test marker, and
``verified`` needs both. A passing build therefore means every status is
consistent; a mismatch is reported as a warning naming the requirement.

.. _coverage-gaps:

Standards coverage
~~~~~~~~~~~~~~~~~~

Sections of BSI TR-03183-2 version 1.1 and the requirements that cover them.

.. needtable::
   :types: spec
   :tags: clause
   :columns: section as "Section";id;references_back as "Covered by"
   :sort: section
   :style: table

Sections with no requirement (an empty table means every section is covered):

.. needtable::
   :types: spec
   :filter: "clause" in tags and len(references_back) == 0
   :columns: section;id;title
   :style: table
