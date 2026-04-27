import os, time, threading, re
import hashlib, pefile, array, math
import pickle, joblib

try:
	import yara
except ImportError:
	yara = None

from db import DB





class ScanVirusAI:
	def get_entropy(self, data):
		if len(data) == 0: return 0.0

		occurences = array.array('L', [0] * 256)

		for x in data:
			if isinstance(x, int): occurences[x] += 1
			else: occurences[ord(x)] += 1

		entropy = 0
		for x in occurences:
			if x:
				p_x = float(x) / len(data)
				entropy -= p_x * math.log(p_x, 2)

		return entropy

	def get_resources(self, pe):
		resources = []
		if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
			try:
				for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
					if hasattr(resource_type, 'directory'):
						for resource_id in resource_type.directory.entries:
							if hasattr(resource_id, 'directory'):
								for resource_lang in resource_id.directory.entries:
									data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
									size = resource_lang.data.struct.Size
									entropy = self.get_entropy(data)
									resources.append([entropy, size])
			except:
				return resources

		return resources

	def get_version_info(self, pe):
		res = {}

		for fileinfo in pe.FileInfo:

			if fileinfo.Key == 'StringFileInfo':
				for st in fileinfo.StringTable:
					for entry in st.entries.items():
						res[entry[0]] = entry[1]

			if fileinfo.Key == 'VarFileInfo':
				for var in fileinfo.Var:
					res[var.entry.items()[0][0]] = var.entry.items()[0][1]


		if hasattr(pe, 'VS_FIXEDFILEINFO'):
			res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
			res['os'] = pe.VS_FIXEDFILEINFO.FileOS
			res['type'] = pe.VS_FIXEDFILEINFO.FileType
			res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
			res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
			res['signature'] = pe.VS_FIXEDFILEINFO.Signature
			res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion

		return res

	def get_file_hashes(self, path):
		sha256_hash = hashlib.sha256()
		md5_hash = hashlib.md5()

		with open(path, 'rb') as file:
			for chunk in iter(lambda: file.read(1024 * 1024), b''):
				sha256_hash.update(chunk)
				md5_hash.update(chunk)

		return sha256_hash.hexdigest(), md5_hash.hexdigest()

	def get_section_name(self, section):
		return section.Name.rstrip(b'\x00').decode(errors='ignore').lower()

	def get_import_names(self, pe):
		imports = set()
		if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
			return imports

		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			for imported_symbol in entry.imports:
				if imported_symbol.name:
					imports.add(imported_symbol.name.decode(errors='ignore').lower())

		return imports

	def read_limited_bytes(self, path, limit=1536 * 1024):
		with open(path, 'rb') as file:
			return file.read(limit)

	def extract_file_strings(self, path):
		data = self.read_limited_bytes(path)
		strings = set()

		for value in re.findall(rb'[\x20-\x7e]{5,}', data):
			strings.add(value.decode(errors='ignore').lower())

		for value in re.findall(rb'(?:[\x20-\x7e]\x00){5,}', data):
			strings.add(value.decode('utf-16le', errors='ignore').lower())

		return strings

	def string_matches(self, strings, needles):
		matches = []
		for needle in needles:
			needle_lower = needle.lower()
			if any(needle_lower in value for value in strings):
				matches.append(needle)
		return matches

	def import_matches(self, imports, names):
		matches = set()
		for import_name in imports:
			for name in names:
				name_lower = name.lower()
				if import_name == name_lower or import_name.startswith(name_lower):
					matches.add(import_name)
		return matches

	def get_path_context(self, path):
		path_lower = path.lower().replace('/', '\\')
		contexts = []

		if '\\appdata\\' in path_lower:
			contexts.append('AppData path')
		if '\\temp\\' in path_lower or '\\tmp\\' in path_lower:
			contexts.append('Temp path')
		if '\\downloads\\' in path_lower:
			contexts.append('Downloads path')
		if '\\startup\\' in path_lower:
			contexts.append('Startup path')
		if '$recycle.bin' in path_lower:
			contexts.append('Recycle Bin path')
		if '\\programdata\\' in path_lower:
			contexts.append('ProgramData path')

		return contexts

	def is_trusted_path(self, path):
		path_lower = path.lower().replace('/', '\\')
		trusted_roots = (
			'c:\\windows\\',
			'c:\\windows\\system32\\',
			'c:\\windows\\syswow64\\',
			'c:\\program files\\',
			'c:\\program files (x86)\\'
		)
		return path_lower.startswith(trusted_roots)

	def is_trusted_vendor_path(self, path):
		path_lower = path.lower().replace('/', '\\')
		trusted_patterns = (
			'c:\\windows\\',
			'c:\\program files\\',
			'c:\\program files (x86)\\',
			'c:\\program files\\microsoft visual studio\\',
			'c:\\program files (x86)\\microsoft visual studio\\',
			'c:\\program files\\microsoft sdks\\',
			'c:\\program files (x86)\\microsoft sdks\\',
			'c:\\windows\\microsoft.net\\',
			'c:\\program files\\windowsapps\\',
			'c:\\program files\\adobe\\',
			'c:\\program files (x86)\\adobe\\',
			'c:\\program files\\common files\\',
			'c:\\program files (x86)\\common files\\',
			'c:\\program files\\nvidia corporation\\',
			'c:\\program files (x86)\\nvidia corporation\\',
			'c:\\program files\\amd\\',
			'c:\\program files\\intel\\',
			'c:\\program files\\nodejs\\',
			'c:\\program files\\python',
			'c:\\program files (x86)\\python',
			'c:\\windows\\system32\\',
			'c:\\windows\\syswow64\\'
		)
		return path_lower.startswith(trusted_patterns)

	def is_user_writable_context(self, indicators):
		user_writable_contexts = {
			'AppData path', 'Temp path', 'Downloads path',
			'Startup path', 'Recycle Bin path', 'ProgramData path'
		}
		return bool(set(indicators['path_context']).intersection(user_writable_contexts))

	def extract_static_indicators(self, path, pe, sha256, md5):
		section_names = {self.get_section_name(section) for section in pe.sections}
		high_entropy_sections = [
			self.get_section_name(section)
			for section in pe.sections
			if section.get_entropy() >= 7.2
		]

		overlay_offset = pe.get_overlay_data_start_offset()
		overlay_size = 0
		if overlay_offset:
			overlay_size = max(os.path.getsize(path) - overlay_offset, 0)

		entry_section = None
		entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		for section in pe.sections:
			start = section.VirtualAddress
			end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
			if start <= entry_point < end:
				entry_section = self.get_section_name(section)
				break

		try:
			imphash = pe.get_imphash()
		except:
			imphash = None

		return {
			'path': path,
			'sha256': sha256,
			'md5': md5,
			'imports': self.get_import_names(pe),
			'strings': self.extract_file_strings(path),
			'section_names': section_names,
			'high_entropy_sections': high_entropy_sections,
			'overlay_size': overlay_size,
			'entry_section': entry_section,
			'imphash': imphash,
			'path_context': self.get_path_context(path),
			'trusted_path': self.is_trusted_path(path),
			'trusted_vendor_path': self.is_trusted_vendor_path(path),
			'file_size': os.path.getsize(path)
		}

	def add_score(self, result, points, label, evidence):
		result['score'] += points
		result['evidence'].append(f"{label}: {evidence} (+{points})")
		result['breakdown'][label] = result['breakdown'].get(label, 0) + points

	def score_trojan_behavior(self, indicators, yara_matches):
		result = {'score': 0, 'evidence': [], 'breakdown': {}}
		imports = indicators['imports']
		strings = indicators['strings']

		yara_rule_names = [match.rule for match in yara_matches]
		trojan_yara_rules = [name for name in yara_rule_names if name.lower().startswith('trojan_')]
		if trojan_yara_rules:
			self.add_score(result, 70, 'YARA Trojan rule', ', '.join(trojan_yara_rules[:3]))

		keylogger_imports = self.import_matches(imports, {'getasynckeystate', 'getkeyboardstate', 'setwindowshookex'})
		if len(keylogger_imports) >= 2:
			self.add_score(result, 35, 'Keylogger APIs', ', '.join(sorted(keylogger_imports)))

		injection_imports = self.import_matches(imports, {'virtualalloc', 'virtualprotect', 'writeprocessmemory', 'createremotethread', 'openprocess'})
		if len(injection_imports) >= 3:
			self.add_score(result, 35, 'Process injection APIs', ', '.join(sorted(injection_imports)))

		network_imports = self.import_matches(imports, {'internetopen', 'internetconnect', 'internetreadfile', 'httpsendrequest', 'winhttpopen', 'winhttpconnect', 'winhttpsendrequest', 'wsastartup', 'connect', 'send', 'recv'})
		if len(network_imports) >= 2:
			self.add_score(result, 25, 'C2/network APIs', ', '.join(sorted(network_imports)[:6]))

		persistence_strings = self.string_matches(strings, ['CurrentVersion\\Run', 'RunOnce', 'schtasks', 'Startup', 'WScript.Shell'])
		if len(persistence_strings) >= 1:
			self.add_score(result, 25, 'Persistence indicators', ', '.join(persistence_strings[:4]))

		stealer_strings = self.string_matches(strings, ['Login Data', 'Local State', 'Cookies', '\\Google\\Chrome\\User Data', '\\Microsoft\\Edge\\User Data', 'CryptUnprotectData'])
		if len(stealer_strings) >= 2:
			self.add_score(result, 35, 'Credential theft indicators', ', '.join(stealer_strings[:5]))

		downloader_strings = self.string_matches(strings, ['URLDownloadToFile', 'WinHttpOpen', 'InternetOpenUrl', 'HttpSendRequest', 'DownloadFile'])
		if len(downloader_strings) >= 2:
			self.add_score(result, 25, 'Downloader indicators', ', '.join(downloader_strings[:5]))

		anti_analysis = self.string_matches(strings, ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'VirtualBox', 'VMware', 'VBoxService'])
		if anti_analysis:
			self.add_score(result, 15, 'Anti-analysis indicators', ', '.join(anti_analysis[:4]))

		if indicators['high_entropy_sections'] and (injection_imports or network_imports):
			self.add_score(result, 20, 'Packed or encrypted behavior', ', '.join(indicators['high_entropy_sections'][:3]))

		if indicators['overlay_size'] > 1024 * 1024 or indicators['overlay_size'] > indicators['file_size'] * 0.2:
			self.add_score(result, 15, 'Large overlay', f"{indicators['overlay_size']} bytes")

		if indicators['path_context']:
			self.add_score(result, 15, 'Suspicious path context', ', '.join(indicators['path_context']))

		if indicators['trusted_path'] and result['score'] < 100:
			result['score'] = max(result['score'] - 50, 0)
			result['evidence'].append('Trusted install/system path: score reduced (-50)')

		return result

	def classify_trojan_family(self, score_result):
		breakdown = score_result['breakdown']

		if breakdown.get('Credential theft indicators', 0) >= 35:
			return 'Stealer'
		if breakdown.get('Keylogger APIs', 0) >= 35:
			return 'Keylogger'
		if breakdown.get('Process injection APIs', 0) >= 35 and breakdown.get('C2/network APIs', 0) >= 25:
			return 'RAT'
		if breakdown.get('Persistence indicators', 0) >= 25 and breakdown.get('C2/network APIs', 0) >= 25:
			return 'Backdoor'
		if breakdown.get('Downloader indicators', 0) >= 25:
			return 'Downloader'
		return 'Suspicious Trojan'

	def build_trojan_detection(self, score_result):
		score = score_result['score']
		if score >= 90:
			confidence = 'HIGH'
		elif score >= 60:
			confidence = 'SUSPICIOUS'
		else:
			return None

		family = self.classify_trojan_family(score_result)
		details = f"{confidence} confidence {family}; score={score}; evidence: " + '; '.join(score_result['evidence'])
		return f"{confidence}:{family}", details

	def is_confirmed_detection(self, detection):
		if not detection:
			return False

		method = detection[0]
		if method.startswith('SUSPICIOUS:'):
			return False

		return True

	def check_heuristics(self, pe, path):
		findings = []
		suspicious_section_names = {
			'.upx', 'upx0', 'upx1', '.aspack', '.adata', '.packed',
			'.themida', '.enigma', '.vmp0', '.vmp1', '.petite'
		}
		dangerous_imports = {
			'virtualalloc', 'virtualprotect', 'writeprocessmemory',
			'createremotethread', 'openprocess', 'loadlibrarya',
			'getprocaddress', 'winexec', 'shellexecutea'
		}

		section_names = {self.get_section_name(section) for section in pe.sections}
		matched_section_names = section_names.intersection(suspicious_section_names)
		if matched_section_names:
			findings.append(f"Suspicious section name: {', '.join(sorted(matched_section_names))}")

		high_entropy_sections = []
		for section in pe.sections:
			entropy = section.get_entropy()
			if entropy >= 7.2:
				high_entropy_sections.append(self.get_section_name(section))

		if high_entropy_sections:
			findings.append(f"High entropy section: {', '.join(high_entropy_sections[:3])}")

		import_names = self.get_import_names(pe)
		if not import_names:
			findings.append("No imports")

		matched_imports = import_names.intersection(dangerous_imports)
		if len(matched_imports) >= 3:
			findings.append(f"Dangerous API combination: {', '.join(sorted(matched_imports)[:5])}")

		entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		for section in pe.sections:
			start = section.VirtualAddress
			end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
			if start <= entry_point < end:
				section_name = self.get_section_name(section)
				section_is_writable = bool(section.Characteristics & 0x80000000)
				if section_is_writable or section_name in suspicious_section_names:
					findings.append(f"Entry point in suspicious section: {section_name}")
				break

		overlay_offset = pe.get_overlay_data_start_offset()
		if overlay_offset:
			file_size = os.path.getsize(path)
			overlay_size = file_size - overlay_offset
			if overlay_size > 1024 * 1024 or overlay_size > file_size * 0.2:
				findings.append(f"Large overlay: {overlay_size} bytes")

		return findings

	def load_yara_rules(self):
		if yara is None:
			return []

		rules_dir = os.path.join('data', 'yara_rules')
		if not os.path.isdir(rules_dir):
			return []

		compiled_rules = []
		for folder_name, sub_folders, filenames in os.walk(rules_dir):
			for filename in filenames:
				if filename.lower().endswith(('.yar', '.yara')):
					rule_path = os.path.join(folder_name, filename)
					try:
						compiled_rules.append(yara.compile(filepath=rule_path))
					except yara.Error as er:
						print(f"[YARA SKIP] Cannot compile {rule_path}: {er}")

		return compiled_rules

	def scan_yara(self, path):
		if not self.yara_rules:
			return []

		matches = []
		for rules in self.yara_rules:
			matches.extend(rules.match(path))

		return matches

	def extract_infos(self, fpath, clf, features):
		res = {}
		pe = pefile.PE(fpath)
		res['Machine'] = pe.FILE_HEADER.Machine
		res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
		res['Characteristics'] = pe.FILE_HEADER.Characteristics
		res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
		res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
		res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
		res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
		res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
		res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
		res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
		res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
		res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
		res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
		res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
		res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
		res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
		res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
		res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
		res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
		res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
		res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
		res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
		res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
		res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
		res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
		res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
		res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
		res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
		res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
		try: res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
		except: res['BaseOfData'] = 0


		res['SectionsNb'] = len(pe.sections)
		entropy = list(map(lambda x: x.get_entropy(), pe.sections))
		res['SectionsMeanEntropy'] = sum(entropy) / float(len((entropy)))
		res['SectionsMinEntropy'] = min(entropy)
		res['SectionsMaxEntropy'] = max(entropy)
		raw_sizes = list(map(lambda x: x.SizeOfRawData, pe.sections))
		res['SectionsMeanRawsize'] = sum(raw_sizes) / float(len((raw_sizes)))
		res['SectionsMinRawsize'] = min(raw_sizes)
		res['SectionsMaxRawsize'] = max(raw_sizes)
		virtual_sizes = list(map(lambda x: x.Misc_VirtualSize, pe.sections))
		res['SectionsMeanVirtualsize'] = sum(virtual_sizes) / float(len(virtual_sizes))
		res['SectionsMinVirtualsize'] = min(virtual_sizes)
		res['SectionMaxVirtualsize'] = max(virtual_sizes)

		try:
			res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
			imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
			res['ImportsNb'] = len(imports)
			res['ImportsNbOrdinal'] = 0
		except:
			res['ImportsNbDLL'] = 0
			res['ImportsNb'] = 0
			res['ImportsNbOrdinal'] = 0

		try: res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
		except: res['ExportNb'] = 0



		resources = self.get_resources(pe)
		res['ResourcesNb'] = len(resources)
		if len(resources) > 0:
			entropy = list(map(lambda x: x[0], resources))
			res['ResourcesMeanEntropy'] = sum(entropy) / float(len(entropy))
			res['ResourcesMinEntropy'] = min(entropy)
			res['ResourcesMaxEntropy'] = max(entropy)
			sizes = list(map(lambda x: x[1], resources))
			res['ResourcesMeanSize'] = sum(sizes) / float(len(sizes))
			res['ResourcesMinSize'] = min(sizes)
			res['ResourcesMaxSize'] = max(sizes)
		else:
			res['ResourcesNb'] = 0
			res['ResourcesMeanEntropy'] = 0
			res['ResourcesMinEntropy'] = 0
			res['ResourcesMaxEntropy'] = 0
			res['ResourcesMeanSize'] = 0
			res['ResourcesMinSize'] = 0
			res['ResourcesMaxSize'] = 0

		try: res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
		except AttributeError: res['LoadConfigurationSize'] = 0

		try:
			version_infos = self.get_version_info(pe)
			res['VersionInformationSize'] = len(version_infos.keys())
		except:
			res['VersionInformationSize'] = 0



		pe_features = list(map(lambda x: res[x], features))
		res = clf.predict([pe_features])[0]

		if res == 0: return True
		else: return False


class ScanVirus(ScanVirusAI):

	def __init__(self):
		self.bad_files = []
		self.detections = {}
		self.PE_files = ['exe', 'dll', 'ocx', 'sys', 'scr', 'drv', 'cpl', 'efi', 'acm', 'ax', 'mui', 'tsp']
		self.clf = joblib.load('data/models/classifier.pkl')
		self.features = pickle.loads(open(os.path.join('data/models/features.pkl'), 'rb').read())
		self.yara_rules = self.load_yara_rules()

	def files_get(self, folder):
		all_paths = []
		skip_dirs = {'node_modules', '.git', '__pycache__', '.venv', 'venv', '.tox', '.mypy_cache', '.pytest_cache', '.gradle', '.idea', '.vs'}
		for folder_name, sub_folder, filenames in os.walk(folder):
			sub_folder[:] = [d for d in sub_folder if d.lower() not in skip_dirs]
			for f in filenames:
				f = f"{folder_name}/{f}"
				all_paths.append(f)

		return all_paths

	def get_file_metadata(self, path):
		try:
			st = os.stat(path)
			return st.st_mtime, st.st_size
		except OSError:
			return None, None

	def should_scan_file(self, path):
		ext = path.rsplit('.', 1)[-1].lower() if '.' in path else ''
		if ext not in self.PE_files:
			return False, 'not-pe'

		base = os.path.basename(path).lower()
		if base in {'pagefile.sys', 'swapfile.sys', 'hiberfil.sys', 'dumpstack.log.tmp'}:
			return False, 'system-file'

		mtime, size = self.get_file_metadata(path)
		if size is None:
			return False, 'unreadable'
		if size < 1024:
			return False, 'too-small'
		if size > 150 * 1024 * 1024:
			return False, 'too-large'

		path_lower = path.lower().replace('/', '\\')
		noisy = ('\\node_modules\\', '\\.git\\', '\\__pycache__\\', '\\.venv\\', '\\venv\\', '\\.gradle\\', '\\.vs\\')
		if any(part in path_lower for part in noisy):
			return False, 'noisy-dir'

		return True, (mtime, size)

	def calculate_fast_risk(self, pe, path):
		score = 0
		reasons = []

		path_lower = path.lower().replace('/', '\\')
		user_writable_markers = ('\\appdata\\', '\\temp\\', '\\tmp\\', '\\downloads\\', '\\startup\\', '$recycle.bin', '\\programdata\\')
		if any(m in path_lower for m in user_writable_markers):
			score += 25
			reasons.append('user-writable path')

		if self.is_trusted_vendor_path(path):
			score -= 50
			reasons.append('trusted vendor path')

		suspicious_section_names = {'.upx', 'upx0', 'upx1', '.aspack', '.adata', '.packed', '.themida', '.enigma', '.vmp0', '.vmp1', '.petite'}
		section_names = {self.get_section_name(s) for s in pe.sections}
		matched_sections = section_names.intersection(suspicious_section_names)
		if matched_sections:
			score += 30
			reasons.append(f"suspicious sections: {','.join(sorted(matched_sections))}")

		high_entropy = [s for s in pe.sections if s.get_entropy() >= 7.2]
		if high_entropy:
			score += 20
			reasons.append('high-entropy section')

		try:
			imports = self.get_import_names(pe)
		except Exception:
			imports = set()

		dangerous_imports = {'virtualalloc', 'virtualprotect', 'writeprocessmemory', 'createremotethread', 'openprocess'}
		matched_imports = imports.intersection(dangerous_imports)
		if len(matched_imports) >= 3:
			score += 30
			reasons.append(f"injection-imports: {len(matched_imports)}")
		elif len(matched_imports) >= 2:
			score += 15

		if not imports:
			score += 15
			reasons.append('no-imports')

		entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		for section in pe.sections:
			start = section.VirtualAddress
			end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
			if start <= entry_point < end:
				if bool(section.Characteristics & 0x80000000) or self.get_section_name(section) in suspicious_section_names:
					score += 20
					reasons.append('entry-point in writable/packed section')
				break

		return score, reasons

	def scanning(self, path):
		ok, meta = self.should_scan_file(path)
		if not ok:
			return

		mtime, size = meta

		try:
			with DB() as db:
				cached = db.get_scan_cache(path, mtime, size)
		except Exception:
			cached = None

		if cached:
			method, details, level = cached
			if level == 'clean':
				return
			if level == 'detected':
				if path not in self.detections:
					self.bad_files.append(path)
					self.detections[path] = (method, details)
				return self.detections[path]
			if level == 'suspicious':
				return (method, details)

		pe = None
		try:
			try:
				pe = pefile.PE(path, fast_load=True)
				pe.parse_data_directories(directories=[
					pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
				])
			except pefile.PEFormatError as er:
				print(f"[SCAN SKIP] Invalid PE: {path} ({er})")
				self._cache_save(path, mtime, size, None, None, 'clean')
				return
			except (OSError, PermissionError, Exception) as er:
				print(f"[SCAN SKIP] Cannot open PE: {path} ({er})")
				return

			risk_score, risk_reasons = self.calculate_fast_risk(pe, path)
			path_user_writable = any(m in path.lower().replace('/', '\\') for m in ('\\appdata\\', '\\temp\\', '\\tmp\\', '\\downloads\\', '\\startup\\', '$recycle.bin', '\\programdata\\'))
			trusted_vendor = self.is_trusted_vendor_path(path)

			needs_hash_check = risk_score >= 20 or path_user_writable or not trusted_vendor
			hash_match = None
			allowlist_match = None
			sha256 = md5 = None

			if needs_hash_check:
				try:
					sha256, md5 = self.get_file_hashes(path)
				except (OSError, PermissionError) as er:
					print(f"[SCAN SKIP] Cannot hash: {path} ({er})")
					return

				with DB() as db:
					hash_match = db.check_virus_hash(sha256, md5)
					allowlist_match = db.check_allowlist_hash(sha256, md5)

				if hash_match:
					self.bad_files.append(path)
					self.detections[path] = ("Hash", f"Hash DB match: {hash_match[2] or hash_match[0]}")
					self._cache_save(path, mtime, size, "Hash", self.detections[path][1], 'detected')
					return self.detections[path]

				if allowlist_match:
					self._cache_save(path, mtime, size, None, None, 'clean')
					return

			deep_scan = (risk_score >= 30) or path_user_writable or (not trusted_vendor and risk_score >= 15)

			if not deep_scan:
				self._cache_save(path, mtime, size, None, None, 'clean')
				return

			try:
				pe.parse_data_directories()
			except Exception:
				pass

			yara_matches = self.scan_yara(path)

			if sha256 is None:
				try:
					sha256, md5 = self.get_file_hashes(path)
				except (OSError, PermissionError):
					sha256 = md5 = None

			indicators = self.extract_static_indicators(path, pe, sha256, md5)
			trojan_score = self.score_trojan_behavior(indicators, yara_matches)
			trojan_detection = self.build_trojan_detection(trojan_score)

			if trojan_detection:
				if self.is_confirmed_detection(trojan_detection):
					self.bad_files.append(path)
					self.detections[path] = trojan_detection
					self._cache_save(path, mtime, size, trojan_detection[0], trojan_detection[1], 'detected')
					return self.detections[path]

				self._cache_save(path, mtime, size, trojan_detection[0], trojan_detection[1], 'suspicious')
				return trojan_detection

			if yara_matches:
				match_names = ', '.join(match.rule for match in yara_matches[:3])
				if indicators['trusted_vendor_path']:
					self._cache_save(path, mtime, size, None, None, 'clean')
					return

				self.bad_files.append(path)
				self.detections[path] = ("YARA", match_names)
				self._cache_save(path, mtime, size, "YARA", match_names, 'detected')
				return self.detections[path]

			heuristic_findings = self.check_heuristics(pe, path)
			if len(heuristic_findings) >= 2:
				if indicators['trusted_vendor_path']:
					self._cache_save(path, mtime, size, None, None, 'clean')
					return
				if self.is_user_writable_context(indicators):
					detection = ("SUSPICIOUS:Heuristic", '; '.join(heuristic_findings))
					self._cache_save(path, mtime, size, detection[0], detection[1], 'suspicious')
					return detection

				self.bad_files.append(path)
				self.detections[path] = ("Heuristic", '; '.join(heuristic_findings))
				self._cache_save(path, mtime, size, "Heuristic", self.detections[path][1], 'detected')
				return self.detections[path]

			try:
				ml_hit = self.extract_infos(path, self.clf, self.features) == True
			except Exception:
				ml_hit = False

			if ml_hit:
				if indicators['trusted_vendor_path']:
					self._cache_save(path, mtime, size, None, None, 'clean')
					return
				if self.is_user_writable_context(indicators):
					detection = ("SUSPICIOUS:ML", "ML model matched in user-writable path; extra evidence required before confirmed detection")
					self._cache_save(path, mtime, size, detection[0], detection[1], 'suspicious')
					return detection

				detection = ("SUSPICIOUS:ML", "ML model matched; not enough supporting evidence for confirmed detection")
				self._cache_save(path, mtime, size, detection[0], detection[1], 'suspicious')
				return detection

			self._cache_save(path, mtime, size, None, None, 'clean')
		except pefile.PEFormatError as er:
			print(f"[SCAN SKIP] Invalid PE: {path} ({er})")
		except (OSError, PermissionError) as er:
			print(f"[SCAN SKIP] Cannot read file: {path} ({er})")
		finally:
			if pe:
				pe.close()

	def _cache_save(self, path, mtime, size, method, details, level):
		try:
			with DB() as db:
				db.save_scan_cache(path, mtime, size, method, details, level)
		except Exception:
			pass

	def scan_all(self, progress_callback, done_callback, status, path, file_callback=None, detection_callback=None):
		if status == 'folder':
			count = 0
			progress_callback(1)

			for folder_name, sub_folders, filenames in os.walk(path):
				sub_folders[:] = [d for d in sub_folders if d.lower() not in {'node_modules', '.git', '__pycache__', '.venv', 'venv', '.tox', '.mypy_cache', '.pytest_cache', '.gradle', '.idea', '.vs', '$recycle.bin', 'system volume information', 'windows.old'}]
				for f in filenames:
					file_path = f"{folder_name}/{f}"
					if file_callback:
						file_callback(file_path)
					try:
						detection = self.scanning(file_path)
					except Exception as er:
						print(f"[SCAN SKIP] {file_path}: {er}")
						detection = None
					if detection and detection_callback:
						detection_callback(file_path, detection[0], detection[1])
					count += 1
					if count % 500 == 0:
						progress_callback((count // 500) % 99 + 1)

			with DB() as db:
				db.add_virus_storage_info([
					(path, self.detections[path][0], self.detections[path][1])
					for path in self.bad_files
				])

			progress_callback(100)
			done_callback()

		elif status == 'file':
			if file_callback:
				file_callback(path)
			detection = self.scanning(path)
			if detection and detection_callback:
				detection_callback(path, detection[0], detection[1])
			if path in self.detections:
				with DB() as db:
					db.add_virus_storage_info([(path, self.detections[path][0], self.detections[path][1])])
			done_callback()






