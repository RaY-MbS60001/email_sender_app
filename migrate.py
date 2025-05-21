from app import app, db
import sqlite3
from sqlalchemy import inspect

def get_columns(table_name):
    """Get existing columns for a table"""
    with sqlite3.connect('email_sender.db') as conn:
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA table_info({table_name})")
        return [column[1] for column in cursor.fetchall()]

def safe_add_column(table_name, column_name, column_type):
    """Safely add a column if it doesn't exist"""
    try:
        existing_columns = get_columns(table_name)
        if column_name not in existing_columns:
            with app.app_context():
                db.engine.execute(f'ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}')
                print(f"Added column {column_name} to {table_name}")
        else:
            print(f"Column {column_name} already exists in {table_name}")
    except Exception as e:
        print(f"Error adding column {column_name} to {table_name}: {e}")

def migrate():
    # Client table columns
    client_columns = [
        ('token', 'TEXT'),
        ('refresh_token', 'TEXT'),
        ('token_uri', 'TEXT'),
        ('client_id', 'TEXT'),
        ('client_secret', 'TEXT'),
        ('scopes', 'TEXT'),
        ('last_login', 'DATETIME')
    ]

    # Batch table columns
    batch_columns = [
        ('cv_filename', 'TEXT'),
        ('error', 'TEXT'),
        ('completed_at', 'DATETIME')
    ]

    print("Starting migration...")

    # Add columns to client table
    for column_name, column_type in client_columns:
        safe_add_column('client', column_name, column_type)

    # Add columns to batch table
    for column_name, column_type in batch_columns:
        safe_add_column('batch', column_name, column_type)

    print("Migration completed")

if __name__ == "__main__":
    migrate()