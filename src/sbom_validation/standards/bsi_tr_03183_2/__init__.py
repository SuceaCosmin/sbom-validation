"""BSI TR-03183-2 rule sets, one module per guideline version."""

from sbom_validation.standards.bsi_tr_03183_2 import v1_1

STANDARD = v1_1.STANDARD

# Guideline version -> rule set. Add a module and an entry per new version.
VERSIONS = {v1_1.VERSION: v1_1.RULE_SET}
