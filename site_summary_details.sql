WITH
    site_scans AS (
        SELECT
            dsi.site_id, dsi.name, s.scan_id, dss.description "status", dsc.started, dsc.finished,
            CASE
                WHEN dse.name ~* 'Internal' THEN 'Internal'
                WHEN dse.name ~* 'External' THEN 'External'
                ELSE 'Other'
            END "scope"
        FROM (
            SELECT site_id, MAX(scan_id) "scan_id"
            FROM dim_site_scan
            GROUP BY site_id
        ) s
        JOIN dim_site dsi USING(site_id)
        JOIN dim_scan dsc USING(scan_id)
        JOIN dim_scan_status dss USING(status_id)
        JOIN dim_site_scan_config USING(site_id)
        JOIN dim_scan_engine dse USING(scan_engine_id)
    ),
    targets AS (
        SELECT site_id, included, target,
            CASE WHEN target ~* '.*-.*' THEN 'range' ELSE 'single' END "addr_type",
            SUBSTRING(target FROM '([0-9.]*)-[0-9.]*') "lo_str",
            SUBSTRING(target FROM '[0-9.]*-([0-9.]*)') "hi_str"
        FROM dim_site_target
        WHERE type = 'ip'
    ),
    network_addresses AS (
        SELECT *,
            NETWORK((
                lo_str || '/' || (32 - CEILING(LOG(2, (hi_int - lo_int + 1))))
            )::INET)::TEXT "network_str"
        FROM (
            SELECT *,
                (SPLIT_PART(lo_str,'.',1)::BIGINT*(256^3)::BIGINT + SPLIT_PART(lo_str,'.',2)::BIGINT*(256^2)::BIGINT +
                    SPLIT_PART(lo_str,'.',3)::BIGINT*256 + SPLIT_PART(lo_str,'.',4)::BIGINT) "lo_int",
                (SPLIT_PART(hi_str,'.',1)::BIGINT*(256^3)::BIGINT + SPLIT_PART(hi_str,'.',2)::BIGINT*(256^2)::BIGINT +
                    SPLIT_PART(hi_str,'.',3)::BIGINT*256 + SPLIT_PART(hi_str,'.',4)::BIGINT) "hi_int"
            FROM targets
        ) t
    ),
    all_addresses AS (
        SELECT t.site_id, t.included, COALESCE(na.network_str, t.target) "address"
        FROM targets t LEFT JOIN network_addresses na USING(site_id, target)
    ),
    summary AS (
        SELECT site_id, included_targets, excluded_targets
        FROM (
            SELECT site_id, STRING_AGG(DISTINCT address, ', ') "included_targets"
            FROM all_addresses WHERE included = 'true' GROUP BY site_id
        ) i
        FULL OUTER JOIN (
            SELECT site_id, STRING_AGG(DISTINCT address, ', ') "excluded_targets"
            FROM all_addresses WHERE included = 'false' GROUP BY site_id
        ) e USING(site_id)
    )

SELECT
    site_id "Site ID", name "Site Name", scan_id "Scan ID",
    scope "Scan Scope", status "Scan Status", started "Scan Start", finished "Scan Finish",
    included_targets "Included Targets", excluded_targets "Excluded Targets"
FROM summary JOIN site_scans USING(site_id)
ORDER BY site_id