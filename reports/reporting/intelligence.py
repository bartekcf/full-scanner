from .cve_policy import is_ignored_cve
            'cvss_score': score, 'cvss_version': cvss_version, 'severity': severity}
        if is_ignored_cve(record):
            continue