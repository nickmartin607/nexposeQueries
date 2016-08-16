WITH
    dim_asset AS ( -- Filters out miscellaneous sites
        SELECT asset_id, ip_address, host_name, operating_system_id, sites
        FROM dim_asset
        WHERE sites !~* '^((SERVICE)|(UNKNOWNS)|(TEST))'
    ),
    dim_aggregated_credential_status AS ( -- Filters out 'N/A' descriptions
        SELECT aggregated_credential_status_id, aggregated_credential_status_description
        FROM dim_aggregated_credential_status
        WHERE aggregated_credential_status_description <> 'N/A'
    ),
    dim_asset_group AS ( -- Filters on DEPT DAG and Orphans
        SELECT asset_group_id, name
        FROM dim_asset_group
        WHERE name ~* '(^DEPT DAG)|(Orphans)'
    ),
    dim_vulnerability_solution AS ( -- Filters on most recent solution per vuln
        SELECT vulnerability_id, MAX(solution_id) "solution_id"
        FROM dim_vulnerability_solution
        GROUP BY vulnerability_id
    ),
    fact_asset_vulnerability_age AS ( -- Filters out old vuln instances
        SELECT asset_id, vulnerability_id, age_in_days, most_recently_discovered
        FROM fact_asset_vulnerability_age
        WHERE age(most_recently_discovered, 'days') < '75'
    ),
    fact_asset_scan_vulnerability_finding AS ( -- Filters out vulns not found in last scan per asset
        SELECT asset_id, vulnerability_id, MAX(scan_id) "scan_id"
        FROM fact_asset_scan_vulnerability_finding
        WHERE scan_id = lastScan(asset_id)
        GROUP BY asset_id, vulnerability_id
    ),
    assets AS ( -- Groups details for an asset
        SELECT da.asset_id, da.ip_address, da.host_name, dos.system, da.sites,
            dag.name, fa.scan_finished, dacs.aggregated_credential_status_description
        FROM dim_asset da
        JOIN fact_asset fa USING(asset_id)
        JOIN dim_asset_group_asset daga USING(asset_id)
        JOIN dim_asset_group dag USING(asset_group_id)
        LEFT JOIN dim_operating_system dos USING(operating_system_id)
        LEFT JOIN dim_aggregated_credential_status dacs USING(aggregated_credential_status_id)
    ),
    vulnerabilities AS ( -- Groups details for a vuln
        SELECT dv.vulnerability_id, dv.title, dv.severity, dv.riskscore,
            dv.cvss_score, ds.summary
        FROM dim_vulnerability dv
        JOIN dim_vulnerability_solution dvs USING(vulnerability_id)
        JOIN dim_solution ds USING(solution_id)
    ),
    facts AS ( -- Groups vuln/scan/asset ids with scan/vuln age
        SELECT fasvf.asset_id, fasvf.vulnerability_id, fasvf.scan_id,
            ds.finished, fava.age_in_days
        FROM fact_asset_scan_vulnerability_finding fasvf
        JOIN dim_scan ds USING(scan_id)
        JOIN fact_asset_vulnerability_age fava USING(asset_id, vulnerability_id)
    ),
    final AS ( -- Formats data for final select
        SELECT
            a.ip_address, a.host_name, a.system, v.title, f.age_in_days, v.severity,
            a.aggregated_credential_status_description, f.asset_id,
            f.scan_id, f.vulnerability_id, f.finished::DATE "finished",
            REGEXP_REPLACE(a.sites, '^DEPT DAG - ', '') "sites",
            REGEXP_REPLACE(name, '(^DEPT DAG - )|\(Internal\)|\(External\)', '', 'g') "name",
            SUBSTRING(v.title FROM 'CVE-\d{4}-\d{4}') "cve_id",
            SUBSTRING(v.title FROM 'MS\d{2}-\d{3}') "ms_patch",
            ROUND(age(a.scan_finished, 'days'), 0) "scan_finished",
            ROUND(v.riskscore::INT, 0) "riskscore",
            ROUND(v.cvss_score::INT, 1) "cvss_score",
            htmlToText(v.summary) "summary",
            CASE WHEN a.sites ~* '(External)|(Outside PFW)' THEN 'External' ELSE 'Internal' END "scope"
        FROM facts f
        JOIN assets a USING(asset_id)
        JOIN vulnerabilities v USING(vulnerability_id)
    )
SELECT
    ip_address "IP Address",            host_name "Hostname",
    system "Operating System",          scope "Scope",
    sites "Site",                       name "Asset Group",
    aggregated_credential_status_description "Credential Status",
    scan_finished "Scan Age",           finished "Date Scan Finished",
    title "Vuln Description",           age_in_days "Vuln Age",
    cve_id "CVE ID",                    ms_patch "MS Patch",
    riskscore "Riskscore",              severity "Severity",
    cvss_score "CVSS",                  summary "Vuln Solution",
    asset_id "AssetID",     scan_id "ScanID",       vulnerability_id "VulnID"
FROM final ORDER BY ip_address, asset_id, vulnerability_id