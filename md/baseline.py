import sqlite3
import os.path

class baseline(object):

    def __init__(self, baseline_file, compare_fields):
        self.initialized = False
        self.mode = "SQL"
        self.items = []
        self.db = None
        self.file = baseline_file
        self.compare_fields = compare_fields
        if self.load():
            self.initialized = True

    def load(self):
        if os.path.isfile(self.file) or self.file == ":memory:":
            self.db = db(self.file)

            if self.db.connection:
                """ Load all required fields from database """
                fields = ""
                for field in self.compare_fields:
                    fields += f"{field}, "
                fields = f"{fields[:-2]}"

                """ The result if any would be a list of tuples """
                self.items = self.db.query(f"SELECT {fields} FROM entries", None)
                if self.items:
                    return True
                else:
                    return False
            else:
                False
        else:
            print(f"WARNING: _baseline.load('{self.file}') -> File not found!")
            return False

    def isfound(self, entry):
        """ Returns False if entry is found in baseline """
        if self.initialized:

            """ Build new_item to check """
            new_item = []
            for field in self.compare_fields:
                new_item.append(entry[field])

            """ Check new_item against baseline items"""
            for item in self.items:
                baseline_item = []

                """ Dynamically build baseline item """
                for field in self.compare_fields:
                    baseline_item.append(item[field])

                if new_item == baseline_item:
                    return True
                baseline_item.clear()
        return False

class db(object):

    def __init__(self, file):

        self.config = ("PRAGMA synchronous = OFF;",
                       "PRAGMA journal_mode = OFF;",
                       "PRAGMA locking_mode = OFF;",  # https://sqlite.org/tempfiles.html
                       "PRAGMA temp_store = MEMORY;",
                       "PRAGMA count_changes = OFF;",
                       "PRAGMA PAGE_SIZE = 4096;",
                       "PRAGMA default_cache_size=700000;",
                       "PRAGMA cache_size=700000;",
                       "PRAGMA compile_options;")

        if file:
            self.file = file
            self.connection = self.open()
        else:
            self.connection = None
            print(f"ERROR: db() ->  connect({file})")

    def open(self):
        try:
            return sqlite3.connect(self.file)
        except Exception as e:
            print(f"ERROR: db() ->  connect({self.file}) -> Msg: {str(e)}")
            return None

    def query(self, query, values=None):

        if self.connection:
            try:

                self.connection.row_factory = sqlite3.Row
                cursor_object = self.connection.cursor()

                if values:
                    result = cursor_object.execute(query, values)
                else:
                    result = cursor_object.execute(query)

                if 'INSERT' in query:
                    self.connection.commit()
                else:
                    rows = result.fetchall()
                    return rows
            except Exception as e:
                print(f"ERROR: db() ->  query({query}) -> Msg: {str(e)}")



    def close(self):
        try:
            self.connection.commit()
            self.connection.close()
        except Exception as e:
            print(f"ERROR: db() ->  close({self.file}) -> Msg: {str(e)}")

    def create(self):
        try:
            cur = self.connection.cursor()

            """ Configure the database """
            for _statement in self.config:
                cur.execute(_statement)
                #self.connection.commit()

            cur.execute(
                '''CREATE TABLE entries(plugin_name text, special text, key_timestamp text, key_subkeys text, key_values text, key_path text, key_path_unicode text, hive_type text,hive_path text, hive_name text, hive_root text, user_sid text, key_value text, value_type text,value_type_str text, value_name text, value_content text, value_content_hash text, value_size text,value_name_unicode text, value_content_unicode)''')

            self.connection.commit()
        except Exception as e:
            print(f"ERROR: db() ->  create({self.file}) -> Msg: {str(e)}")



class _item(object):
    def __init__(self, item_type, key_path, value_name=None, value_content=None):
        self.key_path = key_path
        self.value_name = value_name
        self.value_content = value_content
        if item_type == "KEY":
            self.type = _item_type.KEY
        elif item_type == "VALUE":
            self.type = _item_type.VALUE


class _item_type(_item):
    class KEY:
        pass

    class VALUE:
        pass