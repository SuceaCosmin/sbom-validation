How to read this documentation
==============================

Need types
----------

``spec``
   A standard or specification the product relies on (BSI, CycloneDX, SPDX).
``req``
   A single *shall* statement. Its title names the source section where it
   comes from a standard.
``impl`` / ``test``
   Reserved for explicit implementation and test needs. Today implementation
   and test evidence is read from ``# @need-ids:`` markers in ``src/`` and
   ``tests/`` and shown on each requirement as **code_url** and **test_url**.

Links
-----

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Link
     - Meaning
   * - ``references``
     - the requirement relies on this standard (outgoing); the standard
       shows "is referenced by" (incoming)
   * - ``derived_from``
     - a refined requirement points at its parent requirement
   * - ``implements`` / ``verifies``
     - reserved for explicit ``impl`` and ``test`` needs

Status lifecycle
----------------

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Status
     - Rule
   * - ``draft``
     - proposed, wording not agreed
   * - ``approved``
     - agreed and in scope, no code marker yet
   * - ``implemented``
     - a code marker traces to it, no test marker yet
   * - ``verified``
     - code marker **and** test marker exist
   * - ``deprecated``
     - retired, kept for history

Status is set by hand, but the documentation build checks it against the code
and test markers and fails with a warning naming the requirement when they
disagree (see :doc:`traceability`).

Origin
------

``standard``
   taken from a specification (today BSI TR-03183-2 version 1.1). The
   ``section`` field names the section it comes from.
``product``
   a product decision, for example exit codes or report formats.

Level
-----

``MUST``
   mandatory in the source standard.
``Conditional``
   mandatory only if the element exists and its prerequisites hold. The
   validator checks the *form* of a value that is present and never reports its
   absence.
``n/a``
   a product requirement, not taken from a standard.

Result kind
-----------

``pass-fail``
   decidable from the SBOM; the report shows pass or fail, per component where
   relevant.
``pass-fail-partly-not-verifiable``
   the form is checked (pass or fail) but a further aspect, such as the
   completeness of dependencies, cannot be decided from the SBOM alone.
``form-only``
   present values are checked for form; absence is neither a failure nor
   reported.
``not-verifiable``
   cannot be decided from the SBOM. The report lists the evidence for a human
   reviewer and the exit code is unchanged (see :need:`REQ_CLI_001`).

Release
-------

The release a requirement is planned for or shipped in, for example ``0.1.0``.
The :doc:`roadmap` groups the requirements by release.
