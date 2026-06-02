"""
Vulnerability #2 — Enforce Database-Level Immutability

Creates PostgreSQL triggers that explicitly BLOCK any UPDATE or DELETE
operation on the ``api_documentversion`` and ``api_signaturelog`` tables.

Any attempt to modify or delete a row will raise a PostgreSQL exception:
    "Immutable table: UPDATE/DELETE operations are prohibited on api_<table>"

This ensures that even a direct SQL session (bypassing Django ORM) cannot
silently tamper with the signed audit trail.

NOTE: These triggers are PostgreSQL-specific.  The ``state_operations``
list is intentionally empty — there are no model changes, only raw SQL.
The reverse migration drops the triggers and functions cleanly.
"""
from django.db import migrations


# ---------------------------------------------------------------------------
#  Forward SQL: create immutability triggers
# ---------------------------------------------------------------------------

FORWARD_SQL = """
-- =========================================================================
--  api_documentversion — block UPDATE
-- =========================================================================
CREATE OR REPLACE FUNCTION trg_documentversion_immutable_update()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'Immutable table: UPDATE operations are prohibited on api_documentversion. '
        'Row version_no=% for record_id=% cannot be modified.',
        OLD.version_no, OLD.record_id;
    RETURN NULL;  -- never reached
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_documentversion_no_update ON api_documentversion;
CREATE TRIGGER trg_documentversion_no_update
    BEFORE UPDATE ON api_documentversion
    FOR EACH ROW
    EXECUTE FUNCTION trg_documentversion_immutable_update();

-- =========================================================================
--  api_documentversion — block DELETE
-- =========================================================================
CREATE OR REPLACE FUNCTION trg_documentversion_immutable_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'Immutable table: DELETE operations are prohibited on api_documentversion. '
        'Row version_no=% for record_id=% cannot be removed.',
        OLD.version_no, OLD.record_id;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_documentversion_no_delete ON api_documentversion;
CREATE TRIGGER trg_documentversion_no_delete
    BEFORE DELETE ON api_documentversion
    FOR EACH ROW
    EXECUTE FUNCTION trg_documentversion_immutable_delete();

-- =========================================================================
--  api_signaturelog — block UPDATE
-- =========================================================================
CREATE OR REPLACE FUNCTION trg_signaturelog_immutable_update()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'Immutable table: UPDATE operations are prohibited on api_signaturelog. '
        'Row id=% cannot be modified.',
        OLD.id;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_signaturelog_no_update ON api_signaturelog;
CREATE TRIGGER trg_signaturelog_no_update
    BEFORE UPDATE ON api_signaturelog
    FOR EACH ROW
    EXECUTE FUNCTION trg_signaturelog_immutable_update();

-- =========================================================================
--  api_signaturelog — block DELETE
-- =========================================================================
CREATE OR REPLACE FUNCTION trg_signaturelog_immutable_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'Immutable table: DELETE operations are prohibited on api_signaturelog. '
        'Row id=% cannot be removed.',
        OLD.id;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_signaturelog_no_delete ON api_signaturelog;
CREATE TRIGGER trg_signaturelog_no_delete
    BEFORE DELETE ON api_signaturelog
    FOR EACH ROW
    EXECUTE FUNCTION trg_signaturelog_immutable_delete();
"""


# ---------------------------------------------------------------------------
#  Reverse SQL: drop triggers and functions cleanly
# ---------------------------------------------------------------------------

REVERSE_SQL = """
-- Drop triggers
DROP TRIGGER IF EXISTS trg_documentversion_no_update ON api_documentversion;
DROP TRIGGER IF EXISTS trg_documentversion_no_delete ON api_documentversion;
DROP TRIGGER IF EXISTS trg_signaturelog_no_update     ON api_signaturelog;
DROP TRIGGER IF EXISTS trg_signaturelog_no_delete     ON api_signaturelog;

-- Drop functions
DROP FUNCTION IF EXISTS trg_documentversion_immutable_update();
DROP FUNCTION IF EXISTS trg_documentversion_immutable_delete();
DROP FUNCTION IF EXISTS trg_signaturelog_immutable_update();
DROP FUNCTION IF EXISTS trg_signaturelog_immutable_delete();
"""


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0015_signeddocumentartifact"),
    ]

    operations = [
        migrations.RunSQL(
            sql=FORWARD_SQL,
            reverse_sql=REVERSE_SQL,
            # No state_operations — purely schema-level enforcement
        ),
    ]
