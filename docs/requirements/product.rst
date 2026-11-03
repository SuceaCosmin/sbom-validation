Product requirements
====================

Scope, traceability, command-line behaviour and reporting requirements of the
validator itself (``origin: product``). Only the first two cite a standard
through a ``references`` link; the rest are product decisions. Requirements
taken from a standard are on :doc:`bsi_tr_03183_2_v1_1`; every requirement is
listed, filterable, on the :doc:`register`.

.. req:: Support CycloneDX and SPDX SBOMs
   :id: REQ_FMT_001
   :status: verified
   :origin: product
   :level: n/a
   :release: 0.1.0
   :tags: format, scope
   :references: SPEC_CYCLONEDX_1_4, SPEC_SPDX_2_3

   The validator shall accept SBOM documents in the CycloneDX and SPDX formats.
   The supported serializations and any version-specific constraints shall be
   stated in the applicable format requirements.

.. req:: Trace validation rules to their sources
   :id: REQ_TRACE_001
   :status: verified
   :origin: product
   :level: n/a
   :release: 0.1.0
   :tags: traceability, standards
   :references: SPEC_BSI_TR03183_2_V1_1, SPEC_CYCLONEDX_1_4, SPEC_SPDX_2_3

   Each validation rule shall identify the source specification, its version,
   and the relevant clause or section. BSI-specific requirements shall be
   distinguished from requirements defined by the SBOM format specifications.

.. req:: Preserve requirement-to-test traceability
   :id: REQ_TRACE_002
   :status: verified
   :origin: product
   :level: n/a
   :release: 0.1.0
   :tags: traceability, verification

   Every implementation need shall link to the requirement it implements, and
   every test need shall link to the requirement it verifies.


.. req:: Distinct exit codes
   :id: REQ_CLI_001
   :status: verified
   :origin: product
   :level: n/a
   :release: 0.1.0
   :tags: cli, product

   The validator shall exit with distinct codes for success, non-compliance,
   input problems, usage or configuration problems, and internal failures,
   and shall not change the exit code because of not-verifiable items.

.. req:: Offline operation
   :id: REQ_OFFLINE_001
   :status: verified
   :origin: product
   :level: n/a
   :release: 0.1.0
   :tags: offline, product

   The validator shall run without network access, using schemas and licence
   lists bundled in the package.

.. req:: Console, JSON and HTML reports
   :id: REQ_REPORT_001
   :status: verified
   :origin: product
   :level: n/a
   :release: 0.1.0
   :tags: report, product

   The validator shall write console, JSON and standalone HTML reports that
   describe the same set of results.

.. req:: Report required elements only
   :id: REQ_SEVERITY_001
   :status: implemented
   :origin: product
   :level: n/a
   :release: 0.1.0
   :tags: severity, product

   The validator shall evaluate and report only required elements (MUST,
   SHALL, REQUIRED) of the selected specification version and shall not report
   recommended or optional elements.
