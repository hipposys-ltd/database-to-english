#!/usr/bin/env python3
"""
PostgreSQL Metadata Extractor
Extracts comprehensive metadata from PostgreSQL database and saves to text files.
"""

import psycopg2
import os
from datetime import datetime
import sys
from typing import Dict, List, Tuple, Optional

class PostgreSQLMetadataExtractor:
    def __init__(self, connection_params: Dict[str, str], output_dir: str = "postgres_metadata", include_sample_data: bool = False):
        """
        Initialize the metadata extractor.
        
        Args:
            connection_params: Dictionary with database connection parameters
            output_dir: Directory to store output files
            include_sample_data: Whether to include sample data from tables (default: False)
        """
        self.connection_params = connection_params
        self.output_dir = output_dir
        self.include_sample_data = include_sample_data
        self.conn = None
        self.cursor = None
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Define queries with their descriptions
        self.queries = {
            "01_database_info": {
                "description": "Database Information",
                "query": """
                SELECT 
                    datname as database_name,
                    pg_size_pretty(pg_database_size(datname)) as size,
                    datcollate as collation,
                    datctype as ctype,
                    encoding,
                    datistemplate as is_template,
                    datallowconn as allow_connections
                FROM pg_database
                ORDER BY datname;
                """
            },
            "02_schema_info": {
                "description": "Schema Information",
                "query": """
                SELECT 
                    schema_name,
                    schema_owner,
                    default_character_set_catalog,
                    default_character_set_schema,
                    sql_path
                FROM information_schema.schemata
                ORDER BY schema_name;
                """
            },
            "03_schema_sizes": {
                "description": "Schema Sizes",
                "query": """
                SELECT 
                    schemaname,
                    pg_size_pretty(sum(pg_total_relation_size(schemaname||'.'||tablename))::bigint) as size
                FROM pg_tables 
                GROUP BY schemaname
                ORDER BY sum(pg_total_relation_size(schemaname||'.'||tablename)) DESC;
                """
            },
            "04_table_info": {
                "description": "Table Information",
                "query": """
                SELECT 
                    t.table_catalog,
                    t.table_schema,
                    t.table_name,
                    t.table_type,
                    pg_size_pretty(pg_total_relation_size(t.table_schema||'.'||t.table_name)) as table_size,
                    pg_size_pretty(pg_relation_size(t.table_schema||'.'||t.table_name)) as data_size,
                    pg_size_pretty(pg_total_relation_size(t.table_schema||'.'||t.table_name) - pg_relation_size(t.table_schema||'.'||t.table_name)) as index_size,
                    (SELECT reltuples::bigint FROM pg_class WHERE relname = t.table_name AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = t.table_schema)) as estimated_rows
                FROM information_schema.tables t
                WHERE t.table_schema NOT IN ('information_schema', 'pg_catalog')
                ORDER BY t.table_schema, t.table_name;
                """
            },
            "05_column_info": {
                "description": "Column Information",
                "query": """
                SELECT 
                    c.table_schema,
                    c.table_name,
                    c.column_name,
                    c.ordinal_position,
                    c.column_default,
                    c.is_nullable,
                    c.data_type,
                    c.character_maximum_length,
                    c.numeric_precision,
                    c.numeric_scale,
                    c.datetime_precision,
                    c.is_identity,
                    c.identity_generation,
                    c.is_generated,
                    c.generation_expression,
                    c.is_updatable
                FROM information_schema.columns c
                WHERE c.table_schema NOT IN ('information_schema', 'pg_catalog')
                ORDER BY c.table_schema, c.table_name, c.ordinal_position;
                """
            },
            "06_primary_keys": {
                "description": "Primary Keys",
                "query": """
                SELECT 
                    kcu.table_schema,
                    kcu.table_name,
                    kcu.column_name,
                    kcu.ordinal_position,
                    tc.constraint_name,
                    tc.constraint_type
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu 
                    ON tc.constraint_name = kcu.constraint_name
                    AND tc.table_schema = kcu.table_schema
                    AND tc.table_name = kcu.table_name
                WHERE tc.constraint_type = 'PRIMARY KEY'
                    AND tc.table_schema NOT IN ('information_schema', 'pg_catalog')
                ORDER BY kcu.table_schema, kcu.table_name, kcu.ordinal_position;
                """
            },
            "07_constraints": {
                "description": "All Constraints",
                "query": """
                SELECT 
                    tc.table_schema,
                    tc.table_name,
                    tc.constraint_name,
                    tc.constraint_type,
                    cc.check_clause,
                    rc.unique_constraint_name,
                    rc.match_option,
                    rc.update_rule,
                    rc.delete_rule
                FROM information_schema.table_constraints tc
                LEFT JOIN information_schema.check_constraints cc 
                    ON tc.constraint_name = cc.constraint_name
                LEFT JOIN information_schema.referential_constraints rc 
                    ON tc.constraint_name = rc.constraint_name
                WHERE tc.table_schema NOT IN ('information_schema', 'pg_catalog')
                ORDER BY tc.table_schema, tc.table_name, tc.constraint_type;
                """
            },
            "08_foreign_keys": {
                "description": "Foreign Key Relationships",
                "query": """
                SELECT 
                    kcu.table_schema,
                    kcu.table_name,
                    kcu.column_name,
                    ccu.table_schema AS foreign_table_schema,
                    ccu.table_name AS foreign_table_name,
                    ccu.column_name AS foreign_column_name,
                    rc.constraint_name,
                    rc.update_rule,
                    rc.delete_rule
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu 
                    ON tc.constraint_name = kcu.constraint_name
                JOIN information_schema.constraint_column_usage ccu 
                    ON ccu.constraint_name = tc.constraint_name
                JOIN information_schema.referential_constraints rc 
                    ON tc.constraint_name = rc.constraint_name
                WHERE tc.constraint_type = 'FOREIGN KEY'
                    AND tc.table_schema NOT IN ('information_schema', 'pg_catalog')
                ORDER BY kcu.table_schema, kcu.table_name, kcu.column_name;
                """
            },
            "09_indexes": {
                "description": "Index Information",
                "query": """
                SELECT 
                    n.nspname as schema_name,
                    t.relname as table_name,
                    i.relname as index_name,
                    ix.indisunique as is_unique,
                    ix.indisprimary as is_primary,
                    ix.indisclustered as is_clustered,
                    ix.indisvalid as is_valid,
                    pg_get_indexdef(ix.indexrelid) as index_definition,
                    pg_size_pretty(pg_relation_size(i.oid)) as index_size
                FROM pg_index ix
                JOIN pg_class i ON i.oid = ix.indexrelid
                JOIN pg_class t ON t.oid = ix.indrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                WHERE n.nspname NOT IN ('information_schema', 'pg_catalog')
                ORDER BY n.nspname, t.relname, i.relname;
                """
            },
            "10_views": {
                "description": "Views",
                "query": """
                SELECT 
                    schemaname,
                    viewname,
                    viewowner,
                    definition
                FROM pg_views
                WHERE schemaname NOT IN ('information_schema', 'pg_catalog')
                ORDER BY schemaname, viewname;
                """
            },
            "11_materialized_views": {
                "description": "Materialized Views",
                "query": """
                SELECT 
                    schemaname,
                    matviewname,
                    matviewowner,
                    definition,
                    ispopulated
                FROM pg_matviews
                WHERE schemaname NOT IN ('information_schema', 'pg_catalog')
                ORDER BY schemaname, matviewname;
                """
            },
            "12_functions": {
                "description": "Functions and Procedures",
                "query": """
                SELECT 
                    n.nspname as schema_name,
                    p.proname as function_name,
                    pg_get_function_identity_arguments(p.oid) as arguments,
                    l.lanname as language,
                    p.prokind as kind,
                    p.provolatile as volatility,
                    p.proisstrict as is_strict,
                    p.prosecdef as is_security_definer
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                JOIN pg_language l ON l.oid = p.prolang
                WHERE n.nspname NOT IN ('information_schema', 'pg_catalog')
                ORDER BY n.nspname, p.proname;
                """
            },
            "13_triggers": {
                "description": "Triggers",
                "query": """
                SELECT 
                    n.nspname as schema_name,
                    c.relname as table_name,
                    t.tgname as trigger_name,
                    pg_get_triggerdef(t.oid) as trigger_definition,
                    t.tgenabled as is_enabled,
                    t.tgtype as trigger_type
                FROM pg_trigger t
                JOIN pg_class c ON c.oid = t.tgrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname NOT IN ('information_schema', 'pg_catalog')
                    AND NOT t.tgisinternal
                ORDER BY n.nspname, c.relname, t.tgname;
                """
            },
            "14_sequences": {
                "description": "Sequences",
                "query": """
                SELECT 
                    sequence_schema,
                    sequence_name,
                    data_type,
                    start_value,
                    minimum_value,
                    maximum_value,
                    increment,
                    cycle_option
                FROM information_schema.sequences
                WHERE sequence_schema NOT IN ('information_schema', 'pg_catalog')
                ORDER BY sequence_schema, sequence_name;
                """
            },
            "15_custom_types": {
                "description": "User-Defined Types",
                "query": """
                SELECT 
                    n.nspname as schema_name,
                    t.typname as type_name,
                    t.typtype as type_type,
                    pg_catalog.format_type(t.oid, NULL) as type_definition
                FROM pg_type t
                JOIN pg_namespace n ON n.oid = t.typnamespace
                WHERE n.nspname NOT IN ('information_schema', 'pg_catalog', 'pg_toast')
                    AND t.typtype IN ('c', 'd', 'e', 'r')
                ORDER BY n.nspname, t.typname;
                """
            },
            "16_table_permissions": {
                "description": "Table Permissions",
                "query": """
                SELECT 
                    grantee,
                    table_schema,
                    table_name,
                    privilege_type,
                    is_grantable,
                    grantor
                FROM information_schema.table_privileges
                WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
                ORDER BY table_schema, table_name, grantee;
                """
            },
            "17_roles": {
                "description": "Roles and Users",
                "query": """
                SELECT 
                    rolname as role_name,
                    rolsuper as is_superuser,
                    rolinherit as inherit_privileges,
                    rolcreaterole as can_create_role,
                    rolcreatedb as can_create_db,
                    rolcanlogin as can_login,
                    rolreplication as can_replicate,
                    rolbypassrls as bypass_rls,
                    rolconnlimit as connection_limit,
                    rolvaliduntil as valid_until
                FROM pg_roles
                ORDER BY rolname;
                """
            },
            "18_extensions": {
                "description": "Extensions",
                "query": """
                SELECT 
                    extname as extension_name,
                    extversion as version,
                    n.nspname as schema_name,
                    extrelocatable as is_relocatable
                FROM pg_extension e
                JOIN pg_namespace n ON n.oid = e.extnamespace
                ORDER BY extname;
                """
            },
            "19_tablespaces": {
                "description": "Tablespaces",
                "query": """
                SELECT 
                    spcname as tablespace_name,
                    pg_catalog.pg_get_userbyid(spcowner) as owner,
                    pg_catalog.pg_tablespace_location(oid) as location,
                    spcoptions as options
                FROM pg_tablespace
                ORDER BY spcname;
                """
            },
            "20_statistics": {
                "description": "Table Statistics",
                "query": """
                SELECT 
                    schemaname,
                    tablename,
                    attname as column_name,
                    n_distinct,
                    correlation
                FROM pg_stats
                WHERE schemaname NOT IN ('information_schema', 'pg_catalog')
                ORDER BY schemaname, tablename, attname;
                """
            }
        }
    
    def connect(self) -> bool:
        """Establish database connection."""
        try:
            self.conn = psycopg2.connect(**self.connection_params)
            self.cursor = self.conn.cursor()
            print(f"Connected to PostgreSQL database: {self.connection_params.get('database', 'N/A')}")
            return True
        except Exception as e:
            print(f"Error connecting to database: {e}")
            return False
    
    def disconnect(self):
        """Close database connection."""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
        print("Database connection closed.")
    
    def format_results(self, results: List[Tuple], column_names: List[str]) -> str:
        """Format query results as a readable string."""
        if not results:
            return "No data found.\n"
        
        # Calculate column widths
        widths = []
        for i, col_name in enumerate(column_names):
            max_width = len(col_name)
            for row in results:
                if row[i] is not None:
                    max_width = max(max_width, len(str(row[i])))
            widths.append(min(max_width, 100))  # Limit column width to 100 chars
        
        # Create header
        header = " | ".join(col_name.ljust(width) for col_name, width in zip(column_names, widths))
        separator = "-" * len(header)
        
        # Format rows
        formatted_rows = []
        for row in results:
            formatted_row = " | ".join(
                str(value).ljust(width) if value is not None else "NULL".ljust(width)
                for value, width in zip(row, widths)
            )
            formatted_rows.append(formatted_row)
        
        return f"{header}\n{separator}\n" + "\n".join(formatted_rows) + "\n"
    
    def execute_query(self, query_name: str, query_info: Dict[str, str]) -> bool:
        """Execute a single query and return results (no longer used for single file output)."""
        # This method is kept for backward compatibility but not used in single file mode
        return True
    
    def get_all_tables(self) -> List[Tuple[str, str]]:
        """Get list of all user tables (schema, table_name)."""
        query = """
        SELECT table_schema, table_name
        FROM information_schema.tables
        WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
          AND table_type = 'BASE TABLE'
        ORDER BY table_schema, table_name;
        """
        try:
            self.cursor.execute(query)
            return self.cursor.fetchall()
        except Exception as e:
            print(f"Error getting table list: {e}")
            return []
    
    def extract_sample_data(self, file_handle) -> bool:
        """Extract sample data (first 3 rows) from each table."""
        if not self.include_sample_data:
            return True
        
        print("Extracting sample data from tables...")
        
        # Write sample data header
        file_handle.write(f"\n{'='*80}\n")
        file_handle.write(f"SAMPLE DATA (FIRST 3 ROWS FROM EACH TABLE)\n")
        file_handle.write(f"{'='*80}\n\n")
        
        tables = self.get_all_tables()
        
        if not tables:
            file_handle.write("No user tables found.\n")
            return True
        
        successful_tables = 0
        failed_tables = 0
        
        for schema_name, table_name in tables:
            full_table_name = f"{schema_name}.{table_name}"
            print(f"  Extracting sample data from: {full_table_name}")
            
            try:
                # Use proper SQL identifier quoting to handle special characters
                query = f'SELECT * FROM "{schema_name}"."{table_name}" LIMIT 3;'
                self.cursor.execute(query)
                
                results = self.cursor.fetchall()
                column_names = [desc[0] for desc in self.cursor.description]
                
                # Write table header
                file_handle.write(f"\n{'-'*60}\n")
                file_handle.write(f"TABLE: {full_table_name}\n")
                file_handle.write(f"{'-'*60}\n\n")
                
                if results:
                    # Write formatted sample data
                    formatted_output = self.format_results(results, column_names)
                    file_handle.write(formatted_output)
                    file_handle.write(f"Sample rows: {len(results)}\n")
                else:
                    file_handle.write("No data found in table.\n")
                
                successful_tables += 1
                print(f"    ✓ Success ({len(results)} rows)")
                
            except Exception as e:
                file_handle.write(f"\n{'-'*60}\n")
                file_handle.write(f"TABLE: {full_table_name}\n")
                file_handle.write(f"{'-'*60}\n\n")
                file_handle.write(f"ERROR: {str(e)}\n")
                
                failed_tables += 1
                print(f"    ✗ Error: {e}")
        
        # Write sample data summary
        file_handle.write(f"\n{'-'*60}\n")
        file_handle.write(f"SAMPLE DATA SUMMARY\n")
        file_handle.write(f"{'-'*60}\n\n")
        file_handle.write(f"Successful tables: {successful_tables}\n")
        file_handle.write(f"Failed tables: {failed_tables}\n")
        file_handle.write(f"Total tables: {len(tables)}\n")
        
        print(f"Sample data extraction completed - Success: {successful_tables}, Failed: {failed_tables}")
        return failed_tables == 0
    
    def extract_all_metadata(self) -> bool:
        """Extract all metadata and save to a single file."""
        if not self.connect():
            return False
        
        try:
            print(f"Starting metadata extraction...")
            if self.include_sample_data:
                print("Sample data extraction is ENABLED")
            else:
                print("Sample data extraction is DISABLED")
            
            # Create single output file
            output_file = os.path.join(self.output_dir, f"postgres_metadata_complete.txt")
            
            with open(output_file, 'w', encoding='utf-8') as f:
                # Write header
                f.write("PostgreSQL Complete Metadata Report\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Database: {self.connection_params.get('database', 'N/A')}\n")
                f.write(f"Host: {self.connection_params.get('host', 'N/A')}\n")
                f.write(f"Port: {self.connection_params.get('port', 'N/A')}\n")
                f.write(f"User: {self.connection_params.get('user', 'N/A')}\n")
                f.write(f"Include Sample Data: {self.include_sample_data}\n")
                f.write(f"Extraction Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                
                successful_queries = 0
                failed_queries = 0
                
                for query_name, query_info in self.queries.items():
                    print(f"Executing query: {query_info['description']}")
                    
                    try:
                        self.cursor.execute(query_info['query'])
                        results = self.cursor.fetchall()
                        column_names = [desc[0] for desc in self.cursor.description]
                        
                        # Write section header
                        f.write(f"\n{'='*80}\n")
                        f.write(f"SECTION: {query_info['description'].upper()}\n")
                        f.write(f"{'='*80}\n\n")
                        
                        # Write formatted results
                        formatted_output = self.format_results(results, column_names)
                        f.write(formatted_output)
                        f.write(f"\nTotal rows: {len(results)}\n")
                        
                        successful_queries += 1
                        print(f"  ✓ Success ({len(results)} rows)")
                        
                    except Exception as e:
                        f.write(f"\n{'='*80}\n")
                        f.write(f"SECTION: {query_info['description'].upper()}\n")
                        f.write(f"{'='*80}\n\n")
                        f.write(f"ERROR: {str(e)}\n")
                        
                        failed_queries += 1
                        print(f"  ✗ Error: {e}")
                
                # Extract sample data if enabled
                sample_data_success = self.extract_sample_data(f)
                
                # Write summary at the end
                f.write(f"\n{'='*80}\n")
                f.write(f"EXTRACTION SUMMARY\n")
                f.write(f"{'='*80}\n\n")
                f.write(f"Successful Queries: {successful_queries}\n")
                f.write(f"Failed Queries: {failed_queries}\n")
                f.write(f"Total Sections: {len(self.queries)}\n")
                f.write(f"Sample Data Included: {self.include_sample_data}\n")
                f.write(f"Sample Data Success: {sample_data_success if self.include_sample_data else 'N/A'}\n")
                f.write(f"Completion Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            print("-" * 50)
            print(f"Metadata extraction completed!")
            print(f"Successful queries: {successful_queries}")
            print(f"Failed queries: {failed_queries}")
            print(f"Sample data included: {self.include_sample_data}")
            print(f"Complete report saved to: {os.path.abspath(output_file)}")
            
            return failed_queries == 0
            
        finally:
            self.disconnect()


def main():
    """Main function to run the metadata extractor."""
    
    # Database connection parameters
    # Modify these according to your database configuration
    connection_params = {
        'host': 'localhost',
        'database': 'postgres',
        'user': 'postgres',
        'password': 'postgres',
        'port': '5432'
    }
    
    # You can also use environment variables for security
    # connection_params = {
    #     'host': os.getenv('DB_HOST', 'localhost'),
    #     'database': os.getenv('DB_NAME', 'postgres'),
    #     'user': os.getenv('DB_USER', 'postgres'),
    #     'password': os.getenv('DB_PASSWORD', 'password'),
    #     'port': os.getenv('DB_PORT', '5432')
    # }
    
    # Output directory (will contain single file)
    output_dir = "postgres_metadata"
    
    # Set to True to include sample data (first 3 rows from each table)
    include_sample_data = True
    
    # Create extractor instance
    extractor = PostgreSQLMetadataExtractor(connection_params, output_dir, include_sample_data)
    
    # Extract metadata
    success = extractor.extract_all_metadata()
    
    if success:
        print("\nAll metadata extracted successfully to single file!")
        sys.exit(0)
    else:
        print("\nSome queries failed. Check the output file for details.")
        sys.exit(1)


if __name__ == "__main__":
    main()