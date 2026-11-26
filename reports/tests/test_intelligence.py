from reporting.intelligence import cve_candidates, technology_support


    def test_ignored_cve_identifier_and_alias_are_excluded(self):
        records = [
            cve('CVE-2007-3205'),
            cve(None, advisory_ids=['CVE-2007-3205']),
            cve('CVE-2025-1009'),
        ]
        rows = [row for group in cve_candidates({'cves': records}) for row in group['rows']]
        self.assertEqual([row['identifier'] for row in rows], ['CVE-2025-1009'])