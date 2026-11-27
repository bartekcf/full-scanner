from datetime import date
import unittest

from reporting.intelligence import cve_candidates, technology_support


PHP_CPE = 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*'
WINDOWS_CPE = 'cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*'
DAY = date(2026, 11, 19)


def cve(identifier='CVE-2025-1000', **fields):
    return {
        'cve_id': identifier,
        'product': 'PHP',
        'detected_version': '8.2.4',
        'sources': ['NVD'],
        'match_status': 'potentially_affected',
        'affected_range': PHP_CPE,
        **fields,
    }


def technology(name, version, **fields):
    return {'name': name, 'version': version, 'version_status': 'declared', 'sources': ['http_headers'], **fields}


class LifecycleTests(unittest.TestCase):
    def test_upstream_support_without_cves_and_exact_deadline(self):
        scan = {'technologies': [technology('PHP', '8.2.26'), technology('Bootstrap', '4.6.2')]}
        before = {row['product']: row for row in technology_support(scan, date(2026, 12, 31))}
        after = {row['product']: row for row in technology_support(scan, date(2027, 1, 1))}
        self.assertEqual(before['PHP']['status'], 'supported')
        self.assertEqual(after['PHP']['status'], 'ended')
        self.assertEqual(before['PHP']['id'], after['PHP']['id'])
        self.assertEqual(before['Bootstrap']['status'], 'ended')
        self.assertIn('dostawcy', after['PHP']['recommendation'])
        self.assertEqual(before['PHP']['links'][0]['url'], 'https://www.php.net/supported-versions.php')

    def test_fallbacks_and_precedence(self):
        rows = technology_support(
            {'technologies': [technology('PHP', '8.4.1'), technology('Apache', None)],
             'cves': [cve(detected_version='7.4.33'), cve(product='Node.js', detected_version='18.2.0')]},
            DAY, alert_versions=[('httpd', '2.2.34')],
        )
        by_name = {row['product']: row for row in rows}
        self.assertEqual(by_name['Apache HTTP Server']['status'], 'ended')
        self.assertEqual(by_name['Node.js']['status'], 'ended')
        self.assertEqual(by_name['PHP']['status'], 'supported')
        self.assertEqual(by_name['PHP']['version'], '8.4.1')

    def test_conflict_missing_source_and_no_vendor_guess(self):
        rows = technology_support({'technologies': [
            technology('PHP', '7.4.33', version_conflict=True),
            technology('Node.js', '18.1.2', sources=[]),
            technology('OpenSSL', '8.1.2'),
            technology('nginx', '1.4.0'),
            technology('Django', None),
        ]}, DAY, alert_versions=[('php', '7.4.33')])
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(row['status'] == 'unknown' for row in rows))
        self.assertIn('sprzeczne', next(row for row in rows if row['product'] == 'PHP')['detail'])
        self.assertIn('edycji', next(row for row in rows if row['product'] == 'nginx')['detail'])


class AdvisoryTests(unittest.TestCase):
    def test_nvd_legacy_range_bounds_and_partial_version(self):
        rows = [
            cve(affected_range=f'{PHP_CPE}; versionStartIncluding=8.2.4; versionEndExcluding=8.2.5'),
            cve('CVE-2025-1001', affected_range=f'{PHP_CPE}; versionStartExcluding=8.2.4'),
            cve('CVE-2025-1002', affected_range=f'{PHP_CPE}; versionEndIncluding=8.2.4'),
            cve('CVE-2025-1003', detected_version='8.2'),
            cve('CVE-2025-1004', detected_version='8.2.4-2ubuntu1'),
        ]
        values = {row['identifier']: row['status'] for group in cve_candidates({'cves': rows}) for row in group['rows']}
        self.assertEqual(list(values.values()).count('version_match'), 2)
        self.assertEqual(values['CVE-2025-1001'], 'out_of_range')
        self.assertEqual(values['CVE-2025-1003'], 'insufficient')
        self.assertEqual(values['CVE-2025-1004'], 'insufficient')

    def test_nvd_keeps_structural_conditions_and_disregards_negated_positives(self):
        leaf = {'vulnerable': True, 'criteria': PHP_CPE}
        config = {'operator': 'AND', 'nodes': [
            {'operator': 'OR', 'cpeMatch': [leaf]},
            {'operator': 'OR', 'cpeMatch': [{'vulnerable': False, 'criteria': WINDOWS_CPE}]},
        ]}

        def row(num, configurations):
            return cve(f'CVE-2025-{num}', applicability=[{
                'source': 'NVD', 'target_cpe': PHP_CPE, 'configurations': configurations,
            }])

        rows = cve_candidates({'cves': [row(1000, [config]), row(1001, [{'negate': True, 'cpeMatch': [leaf]}]),
                                       row(1002, [config, {'cpeMatch': [leaf]}])]})[0]['rows']
        result = {item['identifier']: item for item in rows}
        self.assertEqual(result['CVE-2025-1000']['status'], 'conditional')
        self.assertIn('windows_10', result['CVE-2025-1000']['conditions'])
        self.assertEqual(result['CVE-2025-1001']['status'], 'insufficient')
        self.assertEqual(result['CVE-2025-1002']['status'], 'version_match')

    def test_nvd_cpe_target_software_and_backport(self):
        windows_php = 'cpe:2.3:a:php:php:*:*:*:*:*:windows:*:*'
        input_rows = [cve(affected_range=windows_php, description='Only when mod_example is enabled.'),
                      cve('CVE-2025-1001', affected_range=windows_php, backport_status='confirmed_patched')]
        rows = cve_candidates({'cves': input_rows})[0]['rows']
        self.assertEqual([row['status'] for row in rows], ['conditional', 'patched'])
        self.assertIn('windows', rows[0]['conditions'])
        self.assertIn('mod_example', rows[0]['conditions'])

    def test_osv_events_and_github_alternatives(self):
        rows = [
            cve('CVE-2025-1001', sources=['OSV'], osv_id='PYSEC-2025-123', affected_range='introduced 8.1.0, fixed 8.2.4'),
            cve('CVE-2025-1002', sources=['OSV'], affected_range='introduced 0, last_affected 8.2.4'),
            cve(None, ghsa_id='GHSA-1111-2222-3333', sources=['GitHub Security Advisories'],
                applicability=[{'source': 'GHSA', 'ecosystem': 'npm', 'ranges': ['^7.0.0', '>= 8.2.0, < 8.3.0']}]),
            cve('CVE-2025-1003', sources=['OSV'], affected_range='introduced 8.2.0, fixed abcdef'),
        ]
        values = {row['identifier']: row for row in cve_candidates({'cves': rows})[0]['rows']}
        self.assertEqual(values['CVE-2025-1001']['status'], 'out_of_range')
        self.assertIn({'label': 'OSV', 'url': 'https://osv.dev/vulnerability/PYSEC-2025-123'}, values['CVE-2025-1001']['links'])
        self.assertEqual(values['CVE-2025-1002']['status'], 'version_match')
        self.assertEqual(values['GHSA-1111-2222-3333']['status'], 'version_match')
        self.assertEqual(values['CVE-2025-1003']['status'], 'insufficient')

    def test_conflicting_sources_and_unknown_config_do_not_confirm(self):
        data = cve(applicability=[
            {'source': 'NVD', 'target_cpe': PHP_CPE, 'configurations': [{'cpeMatch': [{'criteria': PHP_CPE, 'vulnerable': True}]}]},
            {'source': 'OSV', 'affected': [{'ranges': [
                {'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '8.2.4'}]},
            ]}]},
        ])
        self.assertEqual(cve_candidates({'cves': [data]})[0]['rows'][0]['status'], 'insufficient')

    def test_preserve_valid_rows_count_withdrawn_and_do_not_link_untrusted_values(self):
        records = [cve(f'CVE-2025-{1000 + i}', description='Sensitive URL https://unknown.invalid/?token=SECRET',
                       references=['https://unknown.invalid'], cvss_score=float('nan')) for i in range(20)]
        records.append(cve('CVE-2025-3000', advisory_status='Rejected'))
        records.append(cve('not an identifier'))
        group, = cve_candidates({'cves': records})
        self.assertEqual(group['count'], 22)
        self.assertEqual(len(group['rows']), 20)
        self.assertIsNone(group['rows'][0]['cvss_score'])
        self.assertNotIn('unknown.invalid', str(group))
        self.assertNotIn('SECRET', str(group))
        self.assertEqual(group['rows'][0]['links'][0]['url'], 'https://nvd.nist.gov/vuln/detail/CVE-2025-1000')



if __name__ == '__main__':
    unittest.main()
