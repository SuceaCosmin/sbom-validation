Requirements and standards
==============================

Standards baseline
------------------

.. spec:: BSI TR-03183-2: Software Bill of Materials, version 2.1.0
   :id: SPEC_BSI_TR03183_2
   :tags: standard, sbom

   Initial domain-specific reference for SBOM requirements:
   `official BSI publication
   <https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf?__blob=publicationFile&v=6>`_.

.. spec:: CycloneDX specification, version 1.7
   :id: SPEC_CYCLONEDX_1_7
   :tags: standard, sbom, format

   `Official CycloneDX 1.7 JSON specification
   <https://cyclonedx.org/docs/1.7/json/>`_.

.. spec:: SPDX specification, version 3.0.1
   :id: SPEC_SPDX_3_0_1
   :tags: standard, sbom, format

   `Official SPDX 3.0.1 specification
   <https://spdx.github.io/spdx-spec/v3.0.1/>`_.

Initial requirements
--------------------

.. req:: Support CycloneDX and SPDX SBOMs
   :id: REQ_FMT_001
   :status: open
   :tags: format, scope
   :references: SPEC_CYCLONEDX_1_7, SPEC_SPDX_3_0_1

   The validator shall accept SBOM documents in the CycloneDX and SPDX formats.
   The supported serializations and any version-specific constraints shall be
   stated in the applicable format requirements.

.. req:: Trace validation rules to their sources
   :id: REQ_TRACE_001
   :status: open
   :tags: traceability, standards
   :references: SPEC_BSI_TR03183_2, SPEC_CYCLONEDX_1_7, SPEC_SPDX_3_0_1

   Each validation rule shall identify the source specification, its version,
   and the relevant clause or section. BSI-specific requirements shall be
   distinguished from requirements defined by the SBOM format specifications.

.. req:: Preserve requirement-to-test traceability
   :id: REQ_TRACE_002
   :status: open
   :tags: traceability, verification

   Every implementation need shall link to the requirement it implements, and
   every test need shall link to the requirement it verifies.

Requirement register
--------------------

.. needtable:: Initial requirements
   :tags: scope, traceability
   :columns: id;title;status;references
   :style: table

Traceability workflow
---------------------

Use the following Sphinx-Needs link options when adding artifacts:

* ``:references:`` links requirements to the standards or source documents
  they rely on.
* ``:implements:`` links an implementation need to the requirements it
  implements.
* ``:verifies:`` links a test need to the requirements it verifies.
* ``:derived_from:`` links a refined requirement to its parent requirement.

Record source-derived requirements with stable IDs and exact source/version
citations. Keep the requirements register build warning-free so invalid IDs
and unresolved traceability links are caught during documentation builds.

The checked-in ``ubproject.toml`` configures the same need types and links for
ubCode. Its Codelinks configuration scans ``src/`` and supports Python
``# @need-ids: REQ_FMT_001`` markers to trace implementation locations back to
requirements.
