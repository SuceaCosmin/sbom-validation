SBOM Validation
===============

``sbom-validation`` checks Software Bill of Materials (SBOM) documents in
CycloneDX and SPDX 2.x JSON against BSI TR-03183-2 version 1.1 and reports
each requirement as **pass**, **fail** or **not verifiable**. It runs offline
and writes console, JSON and HTML reports.

This site is the single place to see what the product is required to do, where
each requirement comes from, and the evidence that it is met.

Where to start
--------------

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - I want to…
     - Go to
   * - see how far the product is: what is done, what is open
     - the dashboard below, and the :doc:`roadmap`
   * - find a requirement (search, sort, filter)
     - :doc:`requirements/register`
   * - read what is required and why
     - :doc:`requirements/index` (BSI rules and product requirements)
   * - check a requirement against its standard
     - :doc:`standards` and :doc:`mappings/bsi-tr-03183-2-v1.1`
   * - see whether a requirement is implemented and tested
     - :doc:`traceability`
   * - learn what the statuses, levels and result kinds mean
     - :doc:`reading-guide`
   * - add or change a requirement
     - :doc:`contributing`

Dashboard
---------

Requirements by status, split by where they come from (a *standard* or a
*product* decision). Counts are computed at build time from the requirements
and the code and test markers.

.. needs-summary:: req
   :rows: origin
   :cols: status

By obligation level in the source standard:

.. needs-summary:: req
   :rows: level
   :cols: status

Open work
---------

Requirements that are not yet **verified** (implemented and covered by a
test).

.. needtable::
   :types: req
   :columns: id;title;origin;status;level;release
   :filter: status != "verified"
   :style: table

If the table above is empty, every requirement is verified. Evidence gaps are
listed on :doc:`traceability`.

.. toctree::
   :maxdepth: 2
   :hidden:

   reading-guide
   roadmap
   standards
   requirements/index
   mappings/bsi-tr-03183-2-v1.1
   traceability
   contributing
