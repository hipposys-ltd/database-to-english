#!/usr/bin/env python3
"""
PostgreSQL Metadata Extractor with LLM Data Masking
Extracts comprehensive metadata from PostgreSQL database and saves to text files.
Optionally uses LLM to mask sensitive sample data (only for table data, not metadata).
"""

import psycopg2
import os
from datetime import datetime
import sys
from typing import Dict, List, Tuple, Optional, Union, Iterator
from langchain_aws import ChatBedrock
from langchain_anthropic import ChatAnthropic
from langchain_community.utilities.sql_database import SQLDatabase
from langchain_community.tools.sql_database.tool import QuerySQLDatabaseTool
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage, BaseMessage, SystemMessage, ToolMessage, AIMessage, AIMessageChunk


class PostgreSQLMetadataExtractor:
    def __init__(self, postgres_uri: str, output_dir: str = "postgres_metadata", 
                 include_sample_data: bool = False, mask_sample_data: bool = False):
        """
        Initialize the metadata extractor.
        
        Args:
            postgres_uri: PostgreSQL connection URI (e.g., postgresql://user:pass@host:port/dbname)
            output_dir: Directory to store output files (only used for file operations)
            include_sample_data: Whether to include sample data from tables (default: False)
            mask_sample_data: Whether to mask sensitive data using LLM (default: False)
        """
        self.postgres_uri = postgres_uri
        self.output_dir = output_dir
        self.include_sample_data = include_sample_data
        self.mask_sample_data = mask_sample_data
        self.conn = None
        self.cursor = None
        self._llm = None
        self._db = None
        
        # Create output directory only if it doesn't exist and we might need it
        # This is now optional since streaming doesn't require file operations
        if output_dir and output_dir != "postgres_metadata":
            os.makedirs(output_dir, exist_ok=True)
        
        # Parse connection URI for individual components
        self.connection_params = self._parse_uri(postgres_uri)
        
        # Data masking prompt
        self.masking_prompt = """
        You are a data privacy expert. Your task is to mask sensitive data while preserving the data structure and types.
        
        Rules for data masking:
        1. Keep the same data types (strings remain strings, numbers remain numbers, dates remain dates)
        2. Preserve data patterns and formats
        3. Replace sensitive information with realistic but fake data
        4. Keep referential integrity (same values should map to same masked values)
        5. Preserve NULL values as NULL
        6. Keep data lengths similar to original
        
        For example:
        - Names: "John Smith" → "Alex Johnson" 
        - Emails: "john@company.com" → "alex@example.com"
        - Phone: "555-1234" → "555-9876"
        - SSN: "123-45-6789" → "987-65-4321"
        - Addresses: Keep format but change details
        - IDs: Keep format but change values
        - Dates: Keep realistic dates but change them
        
        Return ONLY the masked data in the same format as provided, without any explanations.
        """
        
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
    
    def _parse_uri(self, uri: str) -> Dict[str, str]:
        """Parse PostgreSQL URI into connection parameters."""
        # Simple URI parsing - in production, consider using urllib.parse
        try:
            # Remove postgresql:// prefix
            if uri.startswith('postgresql://'):
                uri = uri[13:]
            
            # Split user:pass@host:port/database
            if '@' in uri:
                auth, rest = uri.split('@', 1)
                if ':' in auth:
                    user, password = auth.split(':', 1)
                else:
                    user = auth
                    password = ''
            else:
                user = 'postgres'
                password = ''
                rest = uri
            
            if '/' in rest:
                host_port, database = rest.split('/', 1)
            else:
                host_port = rest
                database = 'postgres'
            
            if ':' in host_port:
                host, port = host_port.split(':', 1)
            else:
                host = host_port
                port = '5432'
            
            return {
                'host': host,
                'port': port,
                'database': database,
                'user': user,
                'password': password
            }
        except Exception as e:
            print(f"Error parsing URI: {e}")
            return {
                'host': 'localhost',
                'port': '5432',
                'database': 'postgres',
                'user': 'postgres',
                'password': ''
            }
    
    @property
    def llm(self):
        """Get LLM instance for data masking."""
        if self._llm is None:
            model_config = os.environ.get('LLM_MODEL', 'Anthropic:claude-3-sonnet-20240229')
            model_type, model_id = model_config.split(':', 1)
            
            if model_type == 'Bedrock':
                self._llm = ChatBedrock(
                    model_id=model_id,
                    model_kwargs=dict(temperature=0, max_tokens=8192),
                )
            elif model_type == 'Anthropic':
                self._llm = ChatAnthropic(
                    model=model_id,
                    temperature=0,
                    max_tokens=8192,
                )
            else:
                raise ValueError(f"Unsupported model type: {model_type}")
        return self._llm
    
    @property
    def db(self):
        """Get SQLDatabase instance."""
        if self._db is None:
            self._db = SQLDatabase.from_uri(self.postgres_uri)
        return self._db
    
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
    
    def mask_data_with_llm(self, data_text: str, stream: bool = False) -> Union[str, Iterator[str]]:
        """Mask sensitive data using LLM with optional streaming."""
        if not self.mask_sample_data:
            if stream:
                yield data_text
                return
            return data_text
        
        try:
            messages = [
                SystemMessage(content=self.masking_prompt),
                HumanMessage(content=f"Please mask the following data:\n\n{data_text}")
            ]
            
            if stream:
                print('Stream the LLM response')
                try:
                    for chunk in self.llm.stream(messages):
                        if hasattr(chunk, 'content') and chunk.content:
                            yield chunk.content
                except Exception as stream_error:
                    print(f"Error streaming LLM response: {stream_error}")
                    # Fallback to non-streaming if streaming fails
                    try:
                        response = self.llm.invoke(messages)
                        yield response.content
                    except Exception as fallback_error:
                        print(f"Error with LLM fallback: {fallback_error}")
                        yield data_text
            else:
                response = self.llm.invoke(messages)
                return response.content
                
        except Exception as e:
            print(f"Error masking data with LLM: {e}")
            if stream:
                yield data_text  # Return original data if masking fails
                return
            else:
                return data_text
    
    def _format_plain_table(self, results: List[Tuple], column_names: List[str]) -> str:
        """Format results as plain text table."""
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
    
    def _format_markdown_table(self, results: List[Tuple], column_names: List[str]) -> str:
        """Format results as markdown table."""
        # Create header
        header = "| " + " | ".join(column_names) + " |"
        separator = "| " + " | ".join(["---"] * len(column_names)) + " |"
        
        # Format rows
        formatted_rows = []
        for row in results:
            formatted_values = []
            for value in row:
                if value is None:
                    formatted_values.append("NULL")
                else:
                    # Escape markdown special characters
                    formatted_value = str(value).replace("|", "\\|").replace("\n", " ")
                    formatted_values.append(formatted_value)
            formatted_row = "| " + " | ".join(formatted_values) + " |"
            formatted_rows.append(formatted_row)
        
        return f"{header}\n{separator}\n" + "\n".join(formatted_rows) + "\n"
    
    def get_all_tables_views_mvs(self) -> List[Tuple[str, str, str]]:
        """Get list of all user tables, views, and materialized views (schema, name, type)."""
        query = """
        SELECT 
            table_schema,
            table_name,
            table_type
        FROM information_schema.tables
        WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
        UNION ALL
        SELECT 
            schemaname as table_schema,
            viewname as table_name,
            'VIEW' as table_type
        FROM pg_views
        WHERE schemaname NOT IN ('information_schema', 'pg_catalog')
        UNION ALL
        SELECT 
            schemaname as table_schema,
            matviewname as table_name,
            'MATERIALIZED VIEW' as table_type
        FROM pg_matviews
        WHERE schemaname NOT IN ('information_schema', 'pg_catalog')
        ORDER BY table_schema, table_name;
        """
        try:
            self.cursor.execute(query)
            return self.cursor.fetchall()
        except Exception as e:
            print(f"Error getting tables/views/materialized views list: {e}")
            return []
    
    def get_all_tables(self) -> List[Tuple[str, str]]:
        """Get list of all user tables (schema, table_name) - kept for backward compatibility."""
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
    
    def extract_sample_data(self, file_handle, markdown: bool = False) -> bool:
        """Extract sample data (first 3 rows) from each table, view, and materialized view - for file operations only."""
        if not self.include_sample_data:
            return True
        
        print("Extracting sample data from tables, views, and materialized views...")
        if self.mask_sample_data:
            print("Data masking is ENABLED - sensitive data will be masked using LLM")
        
        # Write sample data header
        if markdown:
            file_handle.write(f"\n## Sample Data (First 3 Rows From Each Table, View, and Materialized View)\n\n")
            if self.mask_sample_data:
                file_handle.write(f"**Note**: Data has been masked for privacy protection\n\n")
        else:
            file_handle.write(f"\n{'='*80}\n")
            file_handle.write(f"SAMPLE DATA (FIRST 3 ROWS FROM EACH TABLE, VIEW, AND MATERIALIZED VIEW)\n")
            if self.mask_sample_data:
                file_handle.write(f"NOTE: Data has been masked for privacy protection\n")
            file_handle.write(f"{'='*80}\n\n")
        
        objects = self.get_all_tables_views_mvs()
        
        if not objects:
            file_handle.write("No user tables, views, or materialized views found.\n")
            return True
        
        successful_objects = 0
        failed_objects = 0
        
        for schema_name, object_name, object_type in objects:
            full_object_name = f"{schema_name}.{object_name}"
            print(f"  Extracting sample data from {object_type.lower()}: {full_object_name}")
            
            try:
                # Use proper SQL identifier quoting to handle special characters
                query = f'SELECT * FROM "{schema_name}"."{object_name}" LIMIT 3;'
                self.cursor.execute(query)
                
                results = self.cursor.fetchall()
                column_names = [desc[0] for desc in self.cursor.description]
                
                # Write object header
                if markdown:
                    file_handle.write(f"\n### {object_type}: {full_object_name}\n\n")
                else:
                    file_handle.write(f"\n{'-'*60}\n")
                    file_handle.write(f"{object_type}: {full_object_name}\n")
                    file_handle.write(f"{'-'*60}\n\n")
                
                if results:
                    # Format and mask sample data - ONLY mask actual data, not metadata
                    formatted_output = self._format_results_for_streaming(results, column_names, markdown)
                    if self.mask_sample_data:
                        formatted_output = self.mask_data_with_llm(formatted_output, stream=False)
                    file_handle.write(formatted_output)
                    
                    if markdown:
                        file_handle.write(f"\n**Sample rows**: {len(results)}\n\n")
                    else:
                        file_handle.write(f"Sample rows: {len(results)}\n")
                else:
                    file_handle.write(f"No data found in {object_type.lower()}.\n")
                
                successful_objects += 1
                print(f"    ✓ Success ({len(results)} rows)")
                
            except Exception as e:
                if markdown:
                    file_handle.write(f"\n### {object_type}: {full_object_name}\n\n")
                    file_handle.write(f"**ERROR**: {str(e)}\n\n")
                else:
                    file_handle.write(f"\n{'-'*60}\n")
                    file_handle.write(f"{object_type}: {full_object_name}\n")
                    file_handle.write(f"{'-'*60}\n\n")
                    file_handle.write(f"ERROR: {str(e)}\n")
                
                failed_objects += 1
                print(f"    ✗ Error: {e}")
        
        # Write sample data summary
        if markdown:
            file_handle.write(f"\n### Sample Data Summary\n\n")
            file_handle.write(f"- **Successful objects**: {successful_objects}\n")
            file_handle.write(f"- **Failed objects**: {failed_objects}\n")
            file_handle.write(f"- **Total objects**: {len(objects)}\n")
            file_handle.write(f"- **Data masking applied**: {self.mask_sample_data}\n\n")
        else:
            file_handle.write(f"\n{'-'*60}\n")
            file_handle.write(f"SAMPLE DATA SUMMARY\n")
            file_handle.write(f"{'-'*60}\n\n")
            file_handle.write(f"Successful objects: {successful_objects}\n")
            file_handle.write(f"Failed objects: {failed_objects}\n")
            file_handle.write(f"Total objects: {len(objects)}\n")
            file_handle.write(f"Data masking applied: {self.mask_sample_data}\n")
        
        print(f"Sample data extraction completed - Success: {successful_objects}, Failed: {failed_objects}")
        return failed_objects == 0
    
    def extract_all_metadata(self, return_as_string: bool = False, markdown: bool = False, 
                           stream_results: bool = False) -> Union[bool, str, Iterator[str]]:
        """Extract all metadata and save to a file, return as string, or stream results."""
        if stream_results:
            # Return generator for streaming - no file operations
            return self._stream_metadata_extraction(markdown)
        
        if return_as_string:
            # Return as string - no file operations
            if not self.connect():
                return ""
            
            try:
                print(f"Starting metadata extraction (return as string)...")
                print(f"Sample data extraction: {'ENABLED' if self.include_sample_data else 'DISABLED'}")
                if self.include_sample_data:
                    print(f"Data masking: {'ENABLED' if self.mask_sample_data else 'DISABLED'}")
                print(f"Output format: {'Markdown' if markdown else 'Plain text'}")
                
                # Generate content directly
                content = self._generate_metadata_content(markdown)
                return content
                
            except Exception as e:
                print(f"Error during metadata extraction: {e}")
                return ""
            finally:
                self.disconnect()
        
        # Original file-based behavior (only when both return_as_string and stream_results are False)
        if not self.connect():
            return False
        
        try:
            print(f"Starting metadata extraction...")
            print(f"Sample data extraction: {'ENABLED' if self.include_sample_data else 'DISABLED'}")
            if self.include_sample_data:
                print(f"Data masking: {'ENABLED' if self.mask_sample_data else 'DISABLED'}")
            print(f"Output format: {'Markdown' if markdown else 'Plain text'}")
            
            # Determine file extension and output file name
            file_extension = "md" if markdown else "txt"
            output_file = os.path.join(self.output_dir, f"postgres_metadata_complete.{file_extension}")
            
            # Create content
            content = self._generate_metadata_content(markdown)
            
            # Save to file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            print("-" * 50)
            print(f"Metadata extraction completed!")
            print(f"Complete report saved to: {os.path.abspath(output_file)}")
            return True
            
        except Exception as e:
            print(f"Error during metadata extraction: {e}")
            return False
        finally:
            self.disconnect()
    
    def _stream_metadata_extraction(self, markdown: bool = False):
        """Stream metadata extraction results after each query - no file operations."""
        if not self.connect():
            yield "Error: Failed to connect to database\n"
            return
        
        try:
            print(f"Starting streaming metadata extraction (no file operations)...")
            print(f"Sample data extraction: {'ENABLED' if self.include_sample_data else 'DISABLED'}")
            if self.include_sample_data:
                print(f"Data masking: {'ENABLED' if self.mask_sample_data else 'DISABLED'}")
            print(f"Output format: {'Markdown' if markdown else 'Plain text'}")
            
            # Yield header immediately
            metadata_str = ''
            if markdown:
                metadata_str += "# PostgreSQL Complete Metadata Report\n\n"
                metadata_str += "## Database Information\n\n"
                metadata_str += f"- **Database**: {self.connection_params.get('database', 'N/A')}\n"
                metadata_str += f"- **Host**: {self.connection_params.get('host', 'N/A')}\n"
                metadata_str += f"- **Port**: {self.connection_params.get('port', 'N/A')}\n"
                metadata_str += f"- **User**: {self.connection_params.get('user', 'N/A')}\n"
                metadata_str += f"- **Include Sample Data**: {self.include_sample_data}\n"
                metadata_str += f"- **Mask Sample Data**: {self.mask_sample_data}\n"
                metadata_str += f"- **Extraction Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            else:
                metadata_str += "PostgreSQL Complete Metadata Report\n"
                metadata_str += "=" * 80 + "\n\n"
                metadata_str += f"Database: {self.connection_params.get('database', 'N/A')}\n"
                metadata_str += f"Host: {self.connection_params.get('host', 'N/A')}\n"
                metadata_str += f"Port: {self.connection_params.get('port', 'N/A')}\n"
                metadata_str += f"User: {self.connection_params.get('user', 'N/A')}\n"
                metadata_str += f"Include Sample Data: {self.include_sample_data}\n"
                metadata_str += f"Mask Sample Data: {self.mask_sample_data}\n"
                metadata_str += f"Extraction Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                metadata_str += "=" * 80 + "\n\n"
            yield metadata_str
            
            successful_queries = 0
            failed_queries = 0
            
            # Execute all queries and yield results after each - DO NOT MASK METADATA
            for query_name, query_info in self.queries.items():
                metadata_str = ''
                print(f"Executing query: {query_info['description']}")
                
                try:
                    self.cursor.execute(query_info['query'])
                    results = self.cursor.fetchall()
                    column_names = [desc[0] for desc in self.cursor.description]
                    
                    # Yield section header
                    if markdown:
                        metadata_str += f"\n## {query_info['description']}\n\n"
                    else:
                        metadata_str += f"\n{'='*80}\n"
                        metadata_str += f"SECTION: {query_info['description'].upper()}\n"
                        metadata_str += f"{'='*80}\n\n"
                    yield metadata_str
                    
                    # Format and yield results - NO MASKING FOR METADATA
                    formatted_output = self._format_results_for_streaming(results, column_names, markdown)
                    yield formatted_output
                    
                    if markdown:
                        yield f"\n**Total rows**: {len(results)}\n\n"
                    else:
                        yield f"\nTotal rows: {len(results)}\n"
                    
                    successful_queries += 1
                    print(f"  ✓ Success ({len(results)} rows)")
                    
                except Exception as e:
                    if markdown:
                        yield f"\n## {query_info['description']}\n\n"
                        yield f"**ERROR**: {str(e)}\n\n"
                    else:
                        yield f"\n{'='*80}\n"
                        yield f"SECTION: {query_info['description'].upper()}\n"
                        yield f"{'='*80}\n\n"
                        yield f"ERROR: {str(e)}\n"
                    
                    failed_queries += 1
                    print(f"  ✗ Error: {e}")
            
            # Stream sample data if enabled (WITH MASKING)
            if self.include_sample_data:
                yield from self._stream_sample_data(markdown)
            
            # Yield summary
            if markdown:
                yield f"\n## Extraction Summary\n\n"
                yield f"- **Successful Queries**: {successful_queries}\n"
                yield f"- **Failed Queries**: {failed_queries}\n"
                yield f"- **Total Sections**: {len(self.queries)}\n"
                yield f"- **Sample Data Included**: {self.include_sample_data}\n"
                yield f"- **Sample Data Masked**: {self.mask_sample_data}\n"
                yield f"- **Completion Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            else:
                yield f"\n{'='*80}\n"
                yield f"EXTRACTION SUMMARY\n"
                yield f"{'='*80}\n\n"
                yield f"Successful Queries: {successful_queries}\n"
                yield f"Failed Queries: {failed_queries}\n"
                yield f"Total Sections: {len(self.queries)}\n"
                yield f"Sample Data Included: {self.include_sample_data}\n"
                yield f"Sample Data Masked: {self.mask_sample_data}\n"
                yield f"Completion Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            
            print(f"Streaming metadata extraction completed - Success: {successful_queries}, Failed: {failed_queries}")
            
        except Exception as e:
            yield f"Error during metadata extraction: {e}\n"
            print(f"Error during metadata extraction: {e}")
        finally:
            self.disconnect()
    
    def _format_results_for_streaming(self, results: List[Tuple], column_names: List[str], markdown: bool = False) -> str:
        """Format results for streaming - returns string directly without file operations."""
        if not results:
            return "No data found.\n"
        
        if markdown:
            return self._format_markdown_table(results, column_names)
        else:
            return self._format_plain_table(results, column_names)
    
    def _stream_sample_data(self, markdown: bool = False):
        """Stream sample data extraction results - no file operations."""
        if not self.include_sample_data:
            return
        
        print("Streaming sample data from tables, views, and materialized views...")
        if self.mask_sample_data:
            print("Data masking is ENABLED - sensitive data will be masked using LLM")
        
        # Yield sample data header
        if markdown:
            yield f"\n## Sample Data (First 3 Rows From Each Table, View, and Materialized View)\n\n"
            if self.mask_sample_data:
                yield f"**Note**: Data has been masked for privacy protection\n\n"
        else:
            yield f"\n{'='*80}\n"
            yield f"SAMPLE DATA (FIRST 3 ROWS FROM EACH TABLE, VIEW, AND MATERIALIZED VIEW)\n"
            if self.mask_sample_data:
                yield f"NOTE: Data has been masked for privacy protection\n"
            yield f"{'='*80}\n\n"
        
        objects = self.get_all_tables_views_mvs()
        
        if not objects:
            yield "No user tables, views, or materialized views found.\n"
            return
        
        successful_objects = 0
        failed_objects = 0
        
        for schema_name, object_name, object_type in objects:
            full_object_name = f"{schema_name}.{object_name}"
            print(f"  Streaming sample data from {object_type.lower()}: {full_object_name}")
            
            try:
                # Use proper SQL identifier quoting to handle special characters
                query = f'SELECT * FROM "{schema_name}"."{object_name}" LIMIT 3;'
                self.cursor.execute(query)
                
                results = self.cursor.fetchall()
                column_names = [desc[0] for desc in self.cursor.description]
                
                # Yield object header
                if markdown:
                    yield f"\n### {object_type}: {full_object_name}\n\n"
                else:
                    yield f"\n{'-'*60}\n"
                    yield f"{object_type}: {full_object_name}\n"
                    yield f"{'-'*60}\n\n"
                
                if results:
                    # Format sample data
                    formatted_output = self._format_results_for_streaming(results, column_names, markdown)
                    
                    # Apply masking ONLY to sample data
                    if self.mask_sample_data:
                        # Stream masked results - handle generator properly
                        for chunk in self.mask_data_with_llm(formatted_output, stream=True):
                            yield chunk
                    else:
                        # Regular formatting - yield the string directly
                        yield formatted_output
                    
                    if markdown:
                        yield f"\n**Sample rows**: {len(results)}\n\n"
                    else:
                        yield f"Sample rows: {len(results)}\n"
                else:
                    yield f"No data found in {object_type.lower()}.\n"
                
                successful_objects += 1
                print(f"    ✓ Success ({len(results)} rows)")
                
            except Exception as e:
                if markdown:
                    yield f"\n### {object_type}: {full_object_name}\n\n"
                    yield f"**ERROR**: {str(e)}\n\n"
                else:
                    yield f"\n{'-'*60}\n"
                    yield f"{object_type}: {full_object_name}\n"
                    yield f"{'-'*60}\n\n"
                    yield f"ERROR: {str(e)}\n"
                
                failed_objects += 1
                print(f"    ✗ Error: {e}")
        
        metadata_str = ''
        # Yield sample data summary
        if markdown:
            metadata_str += f"\n### Sample Data Summary\n\n"
            metadata_str += f"- **Successful objects**: {successful_objects}\n"
            metadata_str += f"- **Failed objects**: {failed_objects}\n"
            metadata_str += f"- **Total objects**: {len(objects)}\n"
            metadata_str += f"- **Data masking applied**: {self.mask_sample_data}\n\n"
        else:
            metadata_str += f"\n{'-'*60}\n"
            metadata_str += f"SAMPLE DATA SUMMARY\n"
            metadata_str += f"{'-'*60}\n\n"
            metadata_str += f"Successful objects: {successful_objects}\n"
            metadata_str += f"Failed objects: {failed_objects}\n"
            metadata_str += f"Total objects: {len(objects)}\n"
            metadata_str += f"Data masking applied: {self.mask_sample_data}\n"
        yield metadata_str
        
        print(f"Sample data streaming completed - Success: {successful_objects}, Failed: {failed_objects}")
    
    def _generate_metadata_content(self, markdown: bool = False) -> str:
        """Generate the complete metadata content for file operations or return as string."""
        content_parts = []
        
        # Write header
        if markdown:
            content_parts.append("# PostgreSQL Complete Metadata Report\n\n")
            content_parts.append("## Database Information\n\n")
            content_parts.append(f"- **Database**: {self.connection_params.get('database', 'N/A')}\n")
            content_parts.append(f"- **Host**: {self.connection_params.get('host', 'N/A')}\n")
            content_parts.append(f"- **Port**: {self.connection_params.get('port', 'N/A')}\n")
            content_parts.append(f"- **User**: {self.connection_params.get('user', 'N/A')}\n")
            content_parts.append(f"- **Include Sample Data**: {self.include_sample_data}\n")
            content_parts.append(f"- **Mask Sample Data**: {self.mask_sample_data}\n")
            content_parts.append(f"- **Extraction Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        else:
            content_parts.append("PostgreSQL Complete Metadata Report\n")
            content_parts.append("=" * 80 + "\n\n")
            content_parts.append(f"Database: {self.connection_params.get('database', 'N/A')}\n")
            content_parts.append(f"Host: {self.connection_params.get('host', 'N/A')}\n")
            content_parts.append(f"Port: {self.connection_params.get('port', 'N/A')}\n")
            content_parts.append(f"User: {self.connection_params.get('user', 'N/A')}\n")
            content_parts.append(f"Include Sample Data: {self.include_sample_data}\n")
            content_parts.append(f"Mask Sample Data: {self.mask_sample_data}\n")
            content_parts.append(f"Extraction Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            content_parts.append("=" * 80 + "\n\n")
        
        successful_queries = 0
        failed_queries = 0
        
        # Execute all queries - DO NOT MASK METADATA
        for query_name, query_info in self.queries.items():
            print(f"Executing query: {query_info['description']}")
            
            try:
                self.cursor.execute(query_info['query'])
                results = self.cursor.fetchall()
                column_names = [desc[0] for desc in self.cursor.description]
                
                # Write section header
                if markdown:
                    content_parts.append(f"\n## {query_info['description']}\n\n")
                else:
                    content_parts.append(f"\n{'='*80}\n")
                    content_parts.append(f"SECTION: {query_info['description'].upper()}\n")
                    content_parts.append(f"{'='*80}\n\n")
                
                # Format results - NO MASKING FOR METADATA
                formatted_output = self._format_results_for_streaming(results, column_names, markdown)
                content_parts.append(formatted_output)
                
                if markdown:
                    content_parts.append(f"\n**Total rows**: {len(results)}\n\n")
                else:
                    content_parts.append(f"\nTotal rows: {len(results)}\n")
                
                successful_queries += 1
                print(f"  ✓ Success ({len(results)} rows)")
                
            except Exception as e:
                if markdown:
                    content_parts.append(f"\n## {query_info['description']}\n\n")
                    content_parts.append(f"**ERROR**: {str(e)}\n\n")
                else:
                    content_parts.append(f"\n{'='*80}\n")
                    content_parts.append(f"SECTION: {query_info['description'].upper()}\n")
                    content_parts.append(f"{'='*80}\n\n")
                    content_parts.append(f"ERROR: {str(e)}\n")
                
                failed_queries += 1
                print(f"  ✗ Error: {e}")
        
        # Extract sample data if enabled (WITH MASKING)
        if self.include_sample_data:
            from io import StringIO
            sample_data_buffer = StringIO()
            sample_data_success = self.extract_sample_data(sample_data_buffer, markdown)
            content_parts.append(sample_data_buffer.getvalue())
        else:
            sample_data_success = True
        
        # Write summary at the end
        if markdown:
            content_parts.append(f"\n## Extraction Summary\n\n")
            content_parts.append(f"- **Successful Queries**: {successful_queries}\n")
            content_parts.append(f"- **Failed Queries**: {failed_queries}\n")
            content_parts.append(f"- **Total Sections**: {len(self.queries)}\n")
            content_parts.append(f"- **Sample Data Included**: {self.include_sample_data}\n")
            content_parts.append(f"- **Sample Data Masked**: {self.mask_sample_data}\n")
            content_parts.append(f"- **Sample Data Success**: {sample_data_success if self.include_sample_data else 'N/A'}\n")
            content_parts.append(f"- **Completion Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        else:
            content_parts.append(f"\n{'='*80}\n")
            content_parts.append(f"EXTRACTION SUMMARY\n")
            content_parts.append(f"{'='*80}\n\n")
            content_parts.append(f"Successful Queries: {successful_queries}\n")
            content_parts.append(f"Failed Queries: {failed_queries}\n")
            content_parts.append(f"Total Sections: {len(self.queries)}\n")
            content_parts.append(f"Sample Data Included: {self.include_sample_data}\n")
            content_parts.append(f"Sample Data Masked: {self.mask_sample_data}\n")
            content_parts.append(f"Sample Data Success: {sample_data_success if self.include_sample_data else 'N/A'}\n")
            content_parts.append(f"Completion Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Store summary info for logging
        self._last_extraction_summary = {
            'successful_queries': successful_queries,
            'failed_queries': failed_queries,
            'sample_data_success': sample_data_success
        }
        
        return "".join(content_parts)

    @staticmethod
    def extract_metadata(postgres_uri: str, output_dir: str = "postgres_metadata", 
                        include_sample_data: bool = False, mask_sample_data: bool = False,
                        return_as_string: bool = False, markdown: bool = False,
                        stream_results: bool = False) -> Union[bool, str, Iterator[str]]:
        """
        Static method to extract metadata from PostgreSQL database.
        
        Args:
            postgres_uri: PostgreSQL connection URI
            output_dir: Directory to store output files
            include_sample_data: Whether to include sample data from tables, views, and materialized views
            mask_sample_data: Whether to mask sensitive data using LLM
            return_as_string: Whether to return content as string instead of saving to file
            markdown: Whether to format output as markdown
            stream_results: Whether to stream results as they're generated
            
        Returns:
            Union[bool, str, Iterator[str]]: 
                - bool: True/False if saving to file
                - str: content if return_as_string=True
                - Iterator[str]: streaming generator if stream_results=True
        """
        extractor = PostgreSQLMetadataExtractor(
            postgres_uri=postgres_uri,
            output_dir=output_dir,
            include_sample_data=include_sample_data,
            mask_sample_data=mask_sample_data
        )
        
        return extractor.extract_all_metadata(
            return_as_string=return_as_string, 
            markdown=markdown,
            stream_results=stream_results
        )


def main():
    """Main function to run the metadata extractor."""
    
    # Example usage - modify these parameters as needed
    postgres_uri = "postgresql://postgres:postgres@localhost:5432/postgres"
    
    # You can also use environment variables
    # postgres_uri = os.getenv('DATABASE_URI', 'postgresql://postgres:postgres@localhost:5432/postgres')
    
    output_dir = "postgres_metadata"
    include_sample_data = True
    mask_sample_data = True  # Set to True to enable data masking
    markdown = True  # Set to True for markdown output
    return_as_string = False  # Set to True to get string instead of file
    
    # Set LLM model (required if mask_sample_data is True)
    if mask_sample_data:
        # Set environment variable for LLM model
        if not os.environ.get('LLM_MODEL'):
            os.environ['LLM_MODEL'] = 'Anthropic:claude-3-sonnet-20240229'
        
        # Set API key if using Anthropic
        if not os.environ.get('ANTHROPIC_API_KEY'):
            print("Warning: ANTHROPIC_API_KEY environment variable not set")
    
    # Extract metadata using static method
    result = PostgreSQLMetadataExtractor.extract_metadata(
        postgres_uri=postgres_uri,
        output_dir=output_dir,
        include_sample_data=include_sample_data,
        mask_sample_data=mask_sample_data,
        return_as_string=return_as_string,
        markdown=markdown
    )
    
    if return_as_string:
        if result:
            print("\nMetadata extracted successfully!")
            print(f"Content length: {len(result)} characters")
            # You can process the string content here
            # print(result[:500])  # Print first 500 characters as preview
        else:
            print("\nMetadata extraction failed.")
        sys.exit(0)
    else:
        if result:
            print("\nAll metadata extracted successfully!")
            sys.exit(0)
        else:
            print("\nSome queries failed. Check the output file for details.")
            sys.exit(1)


if __name__ == "__main__":
    main()