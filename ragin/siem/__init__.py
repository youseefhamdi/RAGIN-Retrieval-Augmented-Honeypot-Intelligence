"""SIEM/SOAR integration — alert forwarding to Splunk, Elastic, and syslog."""

from ragin.siem.connector import SIEMConnector, SIEMEvent, SIEMSeverity
from ragin.siem.elasticsearch import ElasticsearchCEFConnector
from ragin.siem.splunk import SplunkHECConnector
from ragin.siem.syslog import SyslogCEFConnector

__all__ = [
    "SIEMConnector",
    "SIEMEvent",
    "SIEMSeverity",
    "SplunkHECConnector",
    "ElasticsearchCEFConnector",
    "SyslogCEFConnector",
]
