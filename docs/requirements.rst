Requirements and standards
==============================

Standards baseline
------------------

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

Initial requirements
--------------------

.. req:: Support CycloneDX and SPDX SBOMs
   :id: REQ_FMT_001
   :status: open
   :tags: format, scope
   :references: SPEC_CYCLONEDX_1_4, SPEC_SPDX_2_3

   The validator shall accept SBOM documents in the CycloneDX and SPDX formats.
   The supported serializations and any version-specific constraints shall be
   stated in the applicable format requirements.

.. req:: Trace validation rules to their sources
   :id: REQ_TRACE_001
   :status: open
   :tags: traceability, standards
   :references: SPEC_BSI_TR03183_2_V1_1, SPEC_CYCLONEDX_1_4, SPEC_SPDX_2_3

   Each validation rule shall identify the source specification, its version,
   and the relevant clause or section. BSI-specific requirements shall be
   distinguished from requirements defined by the SBOM format specifications.

.. req:: Preserve requirement-to-test traceability
   :id: REQ_TRACE_002
   :status: open
   :tags: traceability, verification

   Every implementation need shall link to the requirement it implements, and
   every test need shall link to the requirement it verifies.


BSI TR-03183-2 version 1.1 requirements
---------------------------------------

.. req:: BSI 1.1 section 4: SBOM format and version
   :id: REQ_BSI11_FORMATS
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall report an SBOM that is not CycloneDX 1.4 or higher, or SPDX 2.3 or higher, as failing the format requirement of BSI TR-03183-2 version 1.1 section 4.

.. req:: BSI 1.1 section 5.1: Recursive dependency resolution
   :id: REQ_BSI11_DEPTH
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall report the recursive dependency resolution required by BSI TR-03183-2 version 1.1 section 5.1 as not verifiable.

.. req:: BSI 1.1 section 5.1: SBOM created in the build process
   :id: REQ_BSI11_BUILD
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall report the creation of the SBOM as part of the build process, required by BSI TR-03183-2 version 1.1 section 5.1, as not verifiable.

.. req:: BSI 1.1 section 5.2.1: SBOM creator
   :id: REQ_BSI11_SBOM_CREATOR
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall report an SBOM that lacks a creator given as an email address, or as a URL where no email address is available, as failing BSI TR-03183-2 version 1.1 section 5.2.1.

.. req:: BSI 1.1 section 5.2.1: SBOM timestamp
   :id: REQ_BSI11_TIMESTAMP
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall report an SBOM that lacks a timestamp in the form the SBOM format specifies as failing BSI TR-03183-2 version 1.1 section 5.2.1.

.. req:: BSI 1.1 section 5.2.2: Component creator
   :id: REQ_BSI11_CMP_CREATOR
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall report each component that lacks a creator given as an email address, or as a URL where no email address is available, as failing BSI TR-03183-2 version 1.1 section 5.2.2.

.. req:: BSI 1.1 section 5.2.2: Component name
   :id: REQ_BSI11_CMP_NAME
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall report each component that lacks a name as failing BSI TR-03183-2 version 1.1 section 5.2.2.

.. req:: BSI 1.1 section 5.2.2: Component version
   :id: REQ_BSI11_CMP_VERSION
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall report each component that lacks a version as failing BSI TR-03183-2 version 1.1 section 5.2.2 and shall not report the use of Semantic or Calendar Versioning.

.. req:: BSI 1.1 section 5.2.2: Component dependencies
   :id: REQ_BSI11_CMP_DEPS
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall evaluate the dependency relationships recorded for each component under BSI TR-03183-2 version 1.1 section 5.2.2 and shall report their completeness as not verifiable.

.. req:: BSI 1.1 section 5.2.2: Component licence
   :id: REQ_BSI11_CMP_LICENCE
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall report each component whose licence is not an SPDX licence identifier or expression, a LicenseRef-scancode- identifier or a LicenseRef-<entity>- identifier as failing BSI TR-03183-2 version 1.1 section 5.2.2, and shall report the correctness of the licence as not verifiable.

.. req:: BSI 1.1 section 5.2.2: Hash of the executable component
   :id: REQ_BSI11_CMP_HASH
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall report each component that lacks a SHA-256 hash of its executable form as failing BSI TR-03183-2 version 1.1 section 5.2.2.

.. req:: BSI 1.1 section 5.3.1: SBOM URI
   :id: REQ_BSI11_SBOM_URI
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall check the form of the SBOM URI, when present, against BSI TR-03183-2 version 1.1 section 5.3.1 and shall not report its absence.

.. req:: BSI 1.1 section 5.3.2: Source code URI
   :id: REQ_BSI11_SRC_URI
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall check the form of the source code URI of each component, when present, against BSI TR-03183-2 version 1.1 section 5.3.2 and shall not report its absence.

.. req:: BSI 1.1 section 5.3.2: URI of the executable form
   :id: REQ_BSI11_EXE_URI
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall check the form of the URI of the executable form of each component, when present, against BSI TR-03183-2 version 1.1 section 5.3.2 and shall not report its absence.

.. req:: BSI 1.1 section 5.3.2: SHA-256 of the source code
   :id: REQ_BSI11_SRC_HASH
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall check the form of the SHA-256 hash of the source code of each component, when present, against BSI TR-03183-2 version 1.1 section 5.3.2 and shall not report its absence.

.. req:: BSI 1.1 section 5.3.2: Other unique identifiers
   :id: REQ_BSI11_OTHER_IDS
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall check the form of the CPE and purl identifiers of each component, when present, against BSI TR-03183-2 version 1.1 section 5.3.2 and shall not report their absence.

.. req:: BSI 1.1 section 3.1: One SBOM per software version
   :id: REQ_BSI11_ONE_PER_VERSION
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall report the requirement of BSI TR-03183-2 version 1.1 section 3.1 for a separate SBOM for each software version as not verifiable.

.. req:: BSI 1.1 section 3.2: Component is a single executable file
   :id: REQ_BSI11_COMPONENT_EXEC
   :status: open
   :tags: bsi, bsi-1-1
   :references: SPEC_BSI_TR03183_2_V1_1

   The validator shall report the requirement of BSI TR-03183-2 version 1.1 section 3.2 that a component corresponds to a single executable file as not verifiable.

Product requirements
--------------------

.. req:: Distinct exit codes
   :id: REQ_CLI_001
   :status: open
   :tags: cli, product

   The validator shall exit with distinct codes for success, non-compliance,
   input problems, usage or configuration problems, and internal failures,
   and shall not change the exit code because of not-verifiable items.

.. req:: Offline operation
   :id: REQ_OFFLINE_001
   :status: open
   :tags: offline, product

   The validator shall run without network access, using schemas and licence
   lists bundled in the package.

.. req:: Console, JSON and HTML reports
   :id: REQ_REPORT_001
   :status: open
   :tags: report, product

   The validator shall write console, JSON and standalone HTML reports that
   describe the same set of results.

.. req:: Report required elements only
   :id: REQ_SEVERITY_001
   :status: open
   :tags: severity, product

   The validator shall evaluate and report only required elements (MUST,
   SHALL, REQUIRED) of the selected specification version and shall not report
   recommended or optional elements.

Requirement register
--------------------

.. needtable:: All requirements
   :types: req
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
