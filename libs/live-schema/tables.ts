export const LIVE_SCHEMAS_TABLE = 'live_schemas';
export const LIVE_USER_SCHEMAS_TABLE = 'live_user_scheams';

export const SCHEMA_EXTRACTOR_DB_ROLE = 'live_schema_extractor';

export const TABLE_DDL: string[] = [
  `CREATE TABLE IF NOT EXISTS ${LIVE_SCHEMAS_TABLE} (
     "udpKey"     varchar(1024) NOT NULL,
     "version"      numeric(10,1) NOT NULL,
     "dateSaved"  timestamptz   NOT NULL,
     "dcatSchema" jsonb         NOT NULL,
     PRIMARY KEY ("udpKey", version)
  )`,
  `CREATE TABLE IF NOT EXISTS ${LIVE_USER_SCHEMAS_TABLE} (
    "udpUserIdHash" varchar(1024) NOT NULL,
    "lastUpdated"   timestamptz   NOT NULL,
    "userSchema"    jsonb         NOT NULL,
    PRIMARY KEY ("udpUserIdHash")
  )`,
];

export interface DbRoleGrant {
  role: string;
  table: string;
  privileges: string[];
}

export const DB_ROLE_GRANTS: DbRoleGrant[] = [
  {
    role: SCHEMA_EXTRACTOR_DB_ROLE,
    table: LIVE_SCHEMAS_TABLE,
    privileges: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
  },
  {
    role: SCHEMA_EXTRACTOR_DB_ROLE,
    table: LIVE_USER_SCHEMAS_TABLE,
    privileges: ['SELECT', 'INSERT', 'UPDATE'],
  },
];
