Roadmap
=======

What ships in which release, and how far each release has progressed. The
``release`` field of a requirement names the release it is planned for or
shipped in.

Progress per release
--------------------

.. needs-summary:: req
   :rows: release
   :cols: status

Open work per release
---------------------

Requirements that are not yet **verified**, grouped by release:

.. needtable::
   :types: req
   :columns: release;id;title;origin;status
   :filter: status not in ("verified", "deprecated")
   :sort: release
   :style: table

All requirements per release
----------------------------

.. needtable::
   :types: req
   :columns: release;id;title;origin;status
   :sort: release
   :style: datatables
