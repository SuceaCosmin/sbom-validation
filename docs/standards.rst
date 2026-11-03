Standards baseline
==================

The specifications this project validates against. Each requirement links to
the standard it relies on through its ``references`` field.

.. spec:: BSI TR-03183-2: Software Bill of Materials, version 1.1
   :id: SPEC_BSI_TR03183_2_V1_1
   :tags: standard, sbom

   First domain-specific reference for SBOM requirements (English edition of
   version 1.1, dated 2023-11-28):
   `official BSI publication
   <https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_2_0.pdf?__blob=publicationFile&v=9>`_.
   The file name says v2_2_0, but the content is version 1.1. Later versions
   will be added progressively.

.. spec:: CycloneDX specification, version 1.4
   :id: SPEC_CYCLONEDX_1_4
   :tags: standard, sbom, format

   `Official CycloneDX 1.4 JSON specification
   <https://cyclonedx.org/docs/1.4/json/>`_. Version 1.4 is the lowest
   CycloneDX version accepted by BSI TR-03183-2 version 1.1; later versions
   up to the newest bundled schema are also supported.

.. spec:: SPDX specification, version 2.3
   :id: SPEC_SPDX_2_3
   :tags: standard, sbom, format

   `Official SPDX 2.3 specification
   <https://spdx.github.io/spdx-spec/v2.3/>`_. Version 2.3 is the lowest SPDX
   version accepted by BSI TR-03183-2 version 1.1. SPDX 3.x is not supported
   in the first release.

BSI TR-03183-2 version 1.1: sections
------------------------------------

One entry per section of the guideline that contains requirements. Each
requirement from the guideline links to its section, so the table below shows
which requirements cover every section. A section with no requirement is a
coverage gap (see :ref:`coverage-gaps`).

.. needtable::
   :types: spec
   :tags: clause
   :columns: section as "Section";id;references_back as "Covered by"
   :sort: section
   :style: table

.. spec:: BSI TR-03183-2 v1.1 Section 3.1
   :id: SPEC_BSI11_S3_1
   :section: 3.1
   :tags: standard, sbom, clause
   :hide:
   :references: SPEC_BSI_TR03183_2_V1_1

   Section 3.1 of BSI TR-03183-2 version 1.1.

.. spec:: BSI TR-03183-2 v1.1 Section 3.2
   :id: SPEC_BSI11_S3_2
   :section: 3.2
   :tags: standard, sbom, clause
   :hide:
   :references: SPEC_BSI_TR03183_2_V1_1

   Section 3.2 of BSI TR-03183-2 version 1.1.

.. spec:: BSI TR-03183-2 v1.1 Section 4: format and version
   :id: SPEC_BSI11_S4
   :section: 4
   :tags: standard, sbom, clause
   :hide:
   :references: SPEC_BSI_TR03183_2_V1_1

   Section 4 of BSI TR-03183-2 version 1.1.

.. spec:: BSI TR-03183-2 v1.1 Section 5.1
   :id: SPEC_BSI11_S5_1
   :section: 5.1
   :tags: standard, sbom, clause
   :hide:
   :references: SPEC_BSI_TR03183_2_V1_1

   Section 5.1 of BSI TR-03183-2 version 1.1.

.. spec:: BSI TR-03183-2 v1.1 Section 5.2.1: SBOM-level fields
   :id: SPEC_BSI11_S5_2_1
   :section: 5.2.1
   :tags: standard, sbom, clause
   :hide:
   :references: SPEC_BSI_TR03183_2_V1_1

   Section 5.2.1 of BSI TR-03183-2 version 1.1.

.. spec:: BSI TR-03183-2 v1.1 Section 5.2.2: component-level fields
   :id: SPEC_BSI11_S5_2_2
   :section: 5.2.2
   :tags: standard, sbom, clause
   :hide:
   :references: SPEC_BSI_TR03183_2_V1_1

   Section 5.2.2 of BSI TR-03183-2 version 1.1.

.. spec:: BSI TR-03183-2 v1.1 Section 5.3.1
   :id: SPEC_BSI11_S5_3_1
   :section: 5.3.1
   :tags: standard, sbom, clause
   :hide:
   :references: SPEC_BSI_TR03183_2_V1_1

   Section 5.3.1 of BSI TR-03183-2 version 1.1.

.. spec:: BSI TR-03183-2 v1.1 Section 5.3.2
   :id: SPEC_BSI11_S5_3_2
   :section: 5.3.2
   :tags: standard, sbom, clause
   :hide:
   :references: SPEC_BSI_TR03183_2_V1_1

   Section 5.3.2 of BSI TR-03183-2 version 1.1.

