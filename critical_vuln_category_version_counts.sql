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
    dim_vulnerability AS ( -- Filters on Critical or Riskscore > 650
        SELECT vulnerability_id, title
        FROM dim_vulnerability
        WHERE severity = 'Critical' OR riskscore > 650
    ),
    fact_asset_scan_vulnerability_finding AS ( -- Filters out most recent instance
        SELECT asset_id, vulnerability_id, MAX(scan_id) "scan_id"
        FROM fact_asset_scan_vulnerability_finding
        WHERE scan_id = lastScan(asset_id)
        GROUP BY asset_id, vulnerability_id
    ),
    vulnerabilities AS ( -- Categorizes vulns
        SELECT vulnerability_id,
            SUBSTRING(title FROM 'MS\d{2}-\d{3}') "ms_patch",
            CASE WHEN title ~* '^sun patch' THEN title END "sun_patch",
            CASE
                WHEN title ~* '^(ms\d{2}-\d{3})' THEN 'ms'
                WHEN title ~* '^sun patch' THEN 'sun'
                WHEN title ~* '(java[^sS])|(jre)' THEN 'java'
                WHEN title ~* '^php' THEN 'php'
                WHEN title ~* '^openssl' THEN 'openssl'
                WHEN title ~* '^isc bind' THEN 'bind'
                WHEN title ~* 'apache httpd' THEN 'apache'
            END "category"
        FROM dim_vulnerability
    ),
    proofs AS ( -- Extracts details from Proof
        SELECT asset_id, vulnerability_id, scan_id,
            SUBSTRING(proof FROM 'Vulnerable software installed: (Oracle JRE.*)\([CD\/][^<>]*\)') "java",
            SUBSTRING(proof FROM 'Vulnerable version of component.*\-\- (PHP[^<>]*)') "php",
            SUBSTRING(proof FROM 'Vulnerable version of component.*\-\- (OpenSSL[^<>]*)') "openssl",
            SUBSTRING(proof FROM 'Vulnerable version of product.*\-\- (BIND[^<>]*)') "bind",
            SUBSTRING(proof FROM 'Vulnerable version of product.*\-\- (Apache HTTPD[^<>]*)') "apache"
        FROM fact_asset_scan_vulnerability_finding
        JOIN fact_asset_scan_vulnerability_instance USING(asset_id, scan_id, vulnerability_id)
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
    summary AS ( -- Counts total vulns per category, and strings together vulnerable versions
        SELECT asset_id,
            NULLIF(SUM((v.category = 'ms')::INT), 0) "ms_ct",
            NULLIF(SUM((v.category = 'sun')::INT), 0) "sun_ct",
            NULLIF(SUM((v.category = 'java')::INT), 0) "java_ct",
            NULLIF(SUM((v.category = 'php')::INT), 0) "php_ct",
            NULLIF(SUM((v.category = 'openssl')::INT), 0) "openssl_ct",
            NULLIF(SUM((v.category = 'bind')::INT), 0) "bind_ct",
            NULLIF(SUM((v.category = 'apache')::INT), 0) "apache_ct",
            STRING_AGG(DISTINCT v.ms_patch, ', ' ORDER BY v.ms_patch DESC) "ms",
            STRING_AGG(DISTINCT v.sun_patch, ', ' ORDER BY v.sun_patch DESC) "sun",
            STRING_AGG(DISTINCT p.java, ', ' ORDER BY p.java DESC) "java",
            STRING_AGG(DISTINCT p.php, ', ' ORDER BY p.php DESC) "php",
            STRING_AGG(DISTINCT p.openssl, ', ' ORDER BY p.openssl DESC) "openssl",
            STRING_AGG(DISTINCT p.bind, ', ' ORDER BY p.bind DESC) "bind",
            STRING_AGG(DISTINCT p.apache, ', ' ORDER BY p.apache DESC) "apache"
        FROM vulnerabilities v
        JOIN proofs p USING(vulnerability_id)
        GROUP BY p.asset_id
    ),
    final AS ( -- Formats data for final select
        SELECT DISTINCT
            a.asset_id, a.ip_address, a.host_name,
            s.ms_ct, s.ms, s.sun_ct, s.sun, s.java_ct, s.java, s.php_ct, s.php,
            s.openssl_ct, s.openssl, s.bind_ct, s.bind, s.apache_ct, s.apache,
            a.aggregated_credential_status_description,
            REGEXP_REPLACE(name, '(^DEPT DAG - )|\(Internal\)|\(External\)', '', 'g') "name",
            REGEXP_REPLACE(a.sites, '^DEPT SITE - ', '') "sites",
            ROUND(age(a.scan_finished, 'days'), 0) "scan_finished",
            CASE WHEN a.sites ~* '(External)|(Outside PFW)' THEN 'External' ELSE 'Internal' END "scope"
        FROM assets a
        JOIN summary s USING(asset_id)
        WHERE s.java_ct > 0 OR s.php_ct > 0 OR s.openssl_ct > 0 OR
            s.bind_ct > 0 OR s.apache_ct > 0 OR s.ms_ct > 0 OR s.sun_ct > 0
    )
SELECT
    name "Asset Group",                 scan_finished "Scan Age",
    ip_address "IP Address",            host_name "Hostname",
    java_ct "Java Total",               java "Java Versions",
    php_ct "PHP Total",                 php "PHP Versions",
    openssl_ct "OpenSSL Total",         openssl "OpenSSL Versions",
    bind_ct "ISC BIND Total",           bind "ISC BIND Versions",
    apache_ct "Apache HTTPD Total",     apache "Apache HTTPD Versions",
    ms_ct "MS Patch Total",             ms "MS Patches",
    sun_ct "Sun Patch Total",           sun "Sun Patches",
    scope "Scope",                      sites "Site",
    aggregated_credential_status_description "Credential Status"
FROM final ORDER BY name, asset_id