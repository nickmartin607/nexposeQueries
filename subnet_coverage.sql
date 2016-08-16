WITH
    dim_site_target AS (SELECT site_id, target, included FROM dim_site_target WHERE type = 'ip'),
    dim_site AS(SELECT site_id, name FROM dim_site WHERE name !~* '(Outside PFW)|(Nexpose)'),

    a AS (
        SELECT site_id, target, included "is_included",
            CASE
                WHEN name ~* 'monthly' THEN REGEXP_REPLACE(name, '^Monthly ', 'M')
                WHEN name ~* 'datacenter' THEN REGEXP_REPLACE(name, '^DATACENTER ', 'DC')
                WHEN name ~* 'dept site' THEN REGEXP_REPLACE(name, '^DEPT SITE - ', '')
                WHEN name ~* 'service site' THEN REGEXP_REPLACE(name, '^SERVICE SITE - ', '')
                WHEN name ~* 'weekly' THEN REGEXP_REPLACE(name, '^WEEKLY - ', '')
                WHEN name ~* 'Primary Data Center' THEN 'PDC'
                WHEN name ~* 'Secondary Data Center' THEN 'SDC'

                ELSE name
            END "name",
            SUBSTRING(target FROM '^([0-9.]*)') "target_lo_str",
            SUBSTRING(target FROM '[0-9.]*-([0-9.]*)') "target_hi_str",
            CASE WHEN target ~* '.*-.*' THEN 'network' ELSE 'single' END "addr_type"
        FROM dim_site_target JOIN dim_site USING(site_id)
    ),
    b AS (
        SELECT *,
            CEILING(LOG(2, (target_hi_int - target_lo_int + 1)))::INT "host_bits",
            (32 - CEILING(LOG(2, (target_hi_int - target_lo_int + 1)))::INT) "mask_bits",
            (2^(CEILING(LOG(2, (target_hi_int - target_lo_int + 1)))::INT) - 2) "subnet_size"
        FROM (
            SELECT *,
                (SPLIT_PART(target_lo_str,'.',1)::BIGINT * (256^3)::BIGINT +
                    SPLIT_PART(target_lo_str,'.',2)::BIGINT * (256^2)::BIGINT +
                    SPLIT_PART(target_lo_str,'.',3)::BIGINT * 256 +
                    SPLIT_PART(target_lo_str,'.',4)::BIGINT
                ) "target_lo_int",
                (SPLIT_PART(target_hi_str,'.',1)::BIGINT * (256^3)::BIGINT +
                    SPLIT_PART(target_hi_str,'.',2)::BIGINT * (256^2)::BIGINT +
                    SPLIT_PART(target_hi_str,'.',3)::BIGINT * 256 +
                    SPLIT_PART(target_hi_str,'.',4)::BIGINT
                ) "target_hi_int"
            FROM a
        ) _a
    ),
    _b AS (
        SELECT site_id, target,
            NETWORK((target_lo_str || '/' || mask_bits)::INET)::TEXT "network_str",
            SPLIT_PART(NETWORK((target_lo_str || '/' || mask_bits)::INET)::TEXT, '/', 1) "subnet_str"
        FROM b WHERE addr_type = 'network'
    ),
    c AS (
        SELECT *,
            CASE WHEN mask_bits < 24 THEN '*' ELSE '' END "notice",
            COALESCE(network_str, target) "target_network_str",
            COALESCE(subnet_str, target) "target_subnet_str"
        FROM b
        LEFT JOIN _b USING(site_id, target)
    ),
    z AS (
        SELECT *,
            (SPLIT_PART(target_subnet_str,'.',1)::BIGINT * (256^3)::BIGINT +
                SPLIT_PART(target_subnet_str,'.',2)::BIGINT * (256^2)::BIGINT +
                SPLIT_PART(target_subnet_str,'.',3)::BIGINT * 256 +
                SPLIT_PART(target_subnet_str,'.',4)::BIGINT
            ) "target_int",
            (SPLIT_PART(target_subnet_str,'.',1)::BIGINT * (256^3)::BIGINT +
                SPLIT_PART(target_subnet_str,'.',2)::BIGINT * (256^2)::BIGINT +
                SPLIT_PART(target_subnet_str,'.',3)::BIGINT * 256
            ) "base_target_int",
            REGEXP_REPLACE(target_subnet_str, '\.\d*$', '.0') "base_target_subnet_str",
            CONCAT(notice, name, '(', target_network_str, ')') "summary_str"
        FROM c
        ORDER BY target_int
    ),
    zz AS (
        SELECT base_target_int, base_target_subnet_str,
            STRING_AGG(CASE WHEN is_included = 'true' THEN summary_str END, E'\r\n' ORDER BY summary_str) "included",
            STRING_AGG(CASE WHEN is_included = 'false' THEN summary_str END, E'\r\n' ORDER BY summary_str) "excluded"
        FROM z
        GROUP BY base_target_subnet_str, base_target_int
        ORDER BY base_target_int
    )
SELECT base_target_subnet_str "Subnet", included "Included", excluded "Excluded" FROM zz