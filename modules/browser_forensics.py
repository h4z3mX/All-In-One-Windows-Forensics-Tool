import os
import sqlite3
import shutil

def extract_edge_data():
    """Extract Edge browser history."""
    edge_history_db = os.path.expanduser('~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History')
    temp_db_path = 'history_copy.db'

    try:
        # Copy the database to avoid file locking issues
        shutil.copy(edge_history_db, temp_db_path)

        # Connect to the copied database
        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()

        # Query to retrieve browsing history
        cursor.execute("SELECT url, title, last_visit_time FROM urls")
        rows = cursor.fetchall()

        history = []
        for row in rows:
            history.append(f"URL: {row[0]}\nTitle: {row[1]}\nLast Visit Time: {row[2]}\n\n")

        conn.close()
        os.remove(temp_db_path)

        return history

    except sqlite3.DatabaseError as e:
        return [f"Database error: {e}"]
    except PermissionError as e:
        return [f"Permission error: {e}"]
    except FileNotFoundError as e:
        return [f"File not found: {e}"]
    except Exception as e:
        return [f"An error occurred: {e}"]
