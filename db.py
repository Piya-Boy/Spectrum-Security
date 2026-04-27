import sqlite3, os, datetime

class DB(object):
	def __init__(self, db_fp='data/data.db'):
		self.db_fp = db_fp
		self.tables = ["virus_md5_hashes", "processed_virusshare_urls", "programm_settings", "virus_storage"]
		self.connect()
		self.create_tables()
		self.programm_settings()

	def __enter__(self):
		return self

	def __exit__(self, type, value, traceback):
		self.conn.commit()
		self.cur.close()
		self.conn.close()

	def __repr__(self):
		return f"<SQLite3 Database: {self.db_fp}>"

	def connect(self):
		self.conn = sqlite3.connect(self.db_fp)
		self.cur = self.conn.cursor()

	def create_tables(self):
		self.cur.execute('CREATE TABLE IF NOT EXISTS programm_settings(setting TEXT NOT NULL, status BOOLEAN NOT NULL)')
		self.cur.execute('CREATE TABLE IF NOT EXISTS virus_storage(date TEXT NOT NULL, path TEXT NOT NULL PRIMARY KEY)')
		virus_storage_columns = [column[1] for column in self.cur.execute("PRAGMA table_info(virus_storage)").fetchall()]
		if 'method' not in virus_storage_columns:
			self.cur.execute("ALTER TABLE virus_storage ADD COLUMN method TEXT DEFAULT 'Malware'")
		if 'details' not in virus_storage_columns:
			self.cur.execute("ALTER TABLE virus_storage ADD COLUMN details TEXT")
		self.cur.execute('''
			CREATE TABLE IF NOT EXISTS virus_hashes(
				sha256 TEXT PRIMARY KEY,
				md5 TEXT,
				name TEXT,
				source TEXT
			)
		''')
		self.cur.execute('CREATE INDEX IF NOT EXISTS idx_virus_hashes_md5 ON virus_hashes(md5)')
		self.cur.execute('''
			CREATE TABLE IF NOT EXISTS allowlist_hashes(
				sha256 TEXT PRIMARY KEY,
				md5 TEXT,
				name TEXT,
				source TEXT
			)
		''')
		self.cur.execute('CREATE INDEX IF NOT EXISTS idx_allowlist_hashes_md5 ON allowlist_hashes(md5)')
		self.cur.execute('''
			CREATE TABLE IF NOT EXISTS scan_cache(
				path TEXT PRIMARY KEY,
				mtime REAL NOT NULL,
				size INTEGER NOT NULL,
				method TEXT,
				details TEXT,
				level TEXT,
				scanned_at TEXT
			)
		''')
		self.conn.commit()

	def get_scan_cache(self, path, mtime, size):
		row = self.cur.execute(
			"SELECT method, details, level FROM scan_cache WHERE path = ? AND mtime = ? AND size = ?",
			[path, mtime, size]
		).fetchone()
		return row

	def save_scan_cache(self, path, mtime, size, method, details, level):
		now = datetime.datetime.now().strftime("%d-%m-%Y %H:%M")
		self.cur.execute(
			"INSERT OR REPLACE INTO scan_cache(path, mtime, size, method, details, level, scanned_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
			[path, mtime, size, method, details, level, now]
		)

	def exists(self, vname, table, value):
		sql = f"SELECT {vname} FROM {table} WHERE {vname} = (?)"
		self.cur.execute(sql, (value,))
		return self.cur.fetchone() is not None

	def reset(self):
		self.close()
		os.remove(self.db_fp)
		self.connect()
		self.update()







	def programm_settings(self):
		if not self.exists('Setting', 'programm_settings', 'Language'):
			self.cur.execute("INSERT INTO programm_settings VALUES (?, ?)", ('Language', True))

	def update_programm_settings(self, setting, status):
		self.cur.execute("UPDATE programm_settings SET status = ? WHERE setting = ?", [status, setting])

	def get_programm_settings(self, setting):
		return self.cur.execute("SELECT status FROM programm_settings WHERE setting = ?", [setting,]).fetchone()

	def add_virus_hash(self, sha256, md5=None, name=None, source=None):
		sha256 = sha256.strip().lower()
		md5 = md5.strip().lower() if md5 else None
		self.cur.execute(
			"INSERT OR IGNORE INTO virus_hashes VALUES(?, ?, ?, ?)",
			[sha256, md5, name, source]
		)

	def check_virus_hash(self, sha256=None, md5=None):
		if sha256:
			data = self.cur.execute(
				"SELECT sha256, md5, name, source FROM virus_hashes WHERE sha256 = ?",
				[sha256.lower()]
			).fetchone()
			if data:
				return data

		if md5:
			return self.cur.execute(
				"SELECT sha256, md5, name, source FROM virus_hashes WHERE md5 = ?",
				[md5.lower()]
			).fetchone()

		return None

	def import_hashes_from_file(self, filepath, source=None):
		imported = 0
		with open(filepath, 'r', encoding='utf-8', errors='ignore') as hash_file:
			for line in hash_file:
				line = line.strip()
				if not line or line.startswith('#'):
					continue

				parts = [part.strip().strip('"').lower() for part in line.replace(';', ',').split(',')]
				sha256 = next((part for part in parts if len(part) == 64 and all(c in '0123456789abcdef' for c in part)), None)
				md5 = next((part for part in parts if len(part) == 32 and all(c in '0123456789abcdef' for c in part)), None)

				if sha256:
					name = next((part for part in parts if part and part != sha256 and part != md5), None)
					self.add_virus_hash(sha256, md5, name, source)
					imported += 1

		return imported

	def add_allowlist_hash(self, sha256, md5=None, name=None, source=None):
		sha256 = sha256.strip().lower()
		md5 = md5.strip().lower() if md5 else None
		self.cur.execute(
			"INSERT OR IGNORE INTO allowlist_hashes VALUES(?, ?, ?, ?)",
			[sha256, md5, name, source]
		)

	def check_allowlist_hash(self, sha256=None, md5=None):
		if sha256:
			data = self.cur.execute(
				"SELECT sha256, md5, name, source FROM allowlist_hashes WHERE sha256 = ?",
				[sha256.lower()]
			).fetchone()
			if data:
				return data

		if md5:
			return self.cur.execute(
				"SELECT sha256, md5, name, source FROM allowlist_hashes WHERE md5 = ?",
				[md5.lower()]
			).fetchone()

		return None

	def import_allowlist_from_file(self, filepath, source=None):
		imported = 0
		with open(filepath, 'r', encoding='utf-8', errors='ignore') as hash_file:
			for line in hash_file:
				line = line.strip()
				if not line or line.startswith('#'):
					continue

				parts = [part.strip().strip('"').lower() for part in line.replace(';', ',').split(',')]
				sha256 = next((part for part in parts if len(part) == 64 and all(c in '0123456789abcdef' for c in part)), None)
				md5 = next((part for part in parts if len(part) == 32 and all(c in '0123456789abcdef' for c in part)), None)

				if sha256:
					name = next((part for part in parts if part and part != sha256 and part != md5), None)
					self.add_allowlist_hash(sha256, md5, name, source)
					imported += 1

		return imported







	def delete_virus_storage_info(self, virus):
		try: self.cur.execute("DELETE FROM virus_storage WHERE path=?", [virus])
		except Exception as er: print(er)

	def add_virus_storage_info(self, viruses, date=None):

		if date == None:
			date = datetime.datetime.now()
			date = date.strftime("%d-%m-%Y %H:%M")

		if type(viruses) == list:
			for virus in viruses:
				if isinstance(virus, tuple):
					path, method, details = virus
				else:
					path, method, details = virus, 'Malware', None
				self.cur.execute(
					"INSERT OR IGNORE INTO virus_storage(date, path, method, details) VALUES(?, ?, ?, ?)",
					[str(date), path, method, details]
				)
		else:
			self.cur.execute(
				"INSERT OR IGNORE INTO virus_storage(date, path, method, details) VALUES(?, ?, ?, ?)",
				[str(date), viruses, 'Malware', None]
			)

	def get_virus_storage_info(self):
		data = self.cur.execute("SELECT date, path, method, details FROM virus_storage").fetchall()
		list_of_lists = [list(elem) for elem in data]
		return list_of_lists
