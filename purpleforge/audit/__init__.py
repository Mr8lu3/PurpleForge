"""
purpleforge.audit — redaction pipeline and tamper-evident hash-chained audit log.

Redaction protects data subjects per UK DPA 2018 / GDPR Article 5(1)(f)
(integrity and confidentiality); audit chain provides forensic integrity for
authorised assessments only, supporting accountability obligations under
UK DPA 2018 Schedule 1 and GDPR Article 5(2).
"""

from purpleforge.audit.redaction import Redactor, redact_text, redact_dict, redactor
from purpleforge.audit.hash_chain import HashChainLog, verify_log
from purpleforge.audit.events import AuditEmitter

__all__ = [
    "Redactor",
    "redact_text",
    "redact_dict",
    "redactor",
    "HashChainLog",
    "verify_log",
    "AuditEmitter",
]
