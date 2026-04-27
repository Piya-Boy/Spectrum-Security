
##==> IMPORT LIBRARIES
####################################################
import sys, os, datetime, psutil, GPUtil, easygui, threading
from winreg import *
from PySide2 import QtWidgets, QtCore, QtGui
from PySide2.QtMultimedia import QSound
from PySide2.QtWidgets import *
from PySide2.QtCore import *
from PySide2.QtGui import *

##==> IMPORT UI FILES
####################################################
from ui import rc_resource
from ui.spectrum_ui_main import Ui_MainWindow as SpectrumSecurityWindow
from ui.spectrum_ui_notify import Ui_MainWindow as SpectrumSecurityNotify
from ui.widgets.circular_progress import CicularProgress
from ui.widgets.toggleswitch import ToggleSwitch

##==> IMPORT OTHER PARTS OF PROJECT
####################################################
from db import DB
from antivirus import ScanVirus










##==> SCAN WORKER THREAD
####################################################
class ScanWorkerThread(QThread):
	progress_updated = Signal(int)
	scan_finished = Signal()
	error_occurred = Signal(str)
	file_updated = Signal(str)
	detection_updated = Signal(str, str, str)

	def __init__(self, status, path):
		QThread.__init__(self)
		self.status = status
		self.path = path

	def run(self):
		try:
			scan = ScanVirus()
			scan.scan_all(
				progress_callback=self.progress_updated.emit,
				done_callback=self.scan_finished.emit,
				status=self.status,
				path=self.path,
				file_callback=self.file_updated.emit,
				detection_callback=self.detection_updated.emit
			)
		except Exception as e:
			import traceback
			traceback.print_exc()
			self.error_occurred.emit(str(e))
			self.scan_finished.emit()


##==> MAIN INTERFACE CLASS
####################################################
class MainWindow(QMainWindow):
	def __init__(self):
		QMainWindow.__init__(self)
		self.ui = SpectrumSecurityWindow()
		self.ui.setupUi(self)

		tray_icon = SystemTrayIcon(QIcon("ui\designer\imgs\general\icon.png"), self)
		tray_icon.show()

		##==> WINDOW OPTIONS
		####################################################
		self.setWindowFlag(QtCore.Qt.FramelessWindowHint)
		self.setAttribute(QtCore.Qt.WA_TranslucentBackground)

		##==> WINDOW BUTTONS
		####################################################
		self.ui.top_menu_minimize_btn.clicked.connect(lambda: self.showMinimized())
		self.ui.top_menu_close_btn.clicked.connect(lambda: self.close())


		##==> EVENTS
		####################################################
		self.ui.top_menu_header.mouseMoveEvent = self.moveWindow

		self.ui.bottom_menu_scroll_area.installEventFilter(self)

		self.ui.bottom_menu_home.installEventFilter(self)
		self.ui.bottom_menu_scanning.installEventFilter(self)
		self.ui.bottom_menu_virus_storage.installEventFilter(self)
		self.ui.bottom_menu_faq.installEventFilter(self)
		self.ui.bottom_menu_settings.installEventFilter(self)

		self.ui.home_secret_way.installEventFilter(self)
		self.ui.scanning_secret_way.installEventFilter(self)
		self.ui.faq_secret_way.installEventFilter(self)
		self.ui.settings_secret_way.installEventFilter(self)


		##==> START WIDGET SETTINGS ON PAGES
		####################################################
		self.home_page_widgets_settings()
		self.scanning_page_widgets_settings()
		self.virus_storage_page_widgets_settings()
		self.faq_page_widgets_settings()
		self.settings_page_widgets_settings()


		self.show()





	##==> HOME PAGE WIDGETS SETTINGS
	####################################################
	def home_page_widgets_settings(self):

		##==> UPDATING INFORMATION ON HOME PAGE
		####################################################
		self.home_timer_update = QTimer(self)
		self.home_timer_update.timeout.connect(lambda: self.main_page_info())
		self.home_timer_update.start(1000)

	def get_cpu_name(self):
		aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
		aKey = OpenKey(aReg, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
		name = QueryValueEx(aKey, 'ProcessorNameString')[0]
		return name

	def main_page_info(self):

		gpus = GPUtil.getGPUs()


		with DB() as db:
			lang = bool(db.get_programm_settings('Language')[0])

		self.ui.CPU_progress.setText(f'CPU - {round(psutil.cpu_percent())}%')
		self.ui.RAM_progress.setText(f'RAM - {round(psutil.virtual_memory().percent)}%')


		if lang:
			self.ui.CPU_info.setText(f"Model - {self.get_cpu_name()}")
			self.ui.Physical_cores_info.setText(f'Physical cores - {psutil.cpu_count(logical=True)}')
			self.ui.Frequency_info.setText(f'Frequency - {psutil.cpu_freq().current:.2f}MHz')

			self.ui.RAM_total_info.setText(f'Total - {round(psutil.virtual_memory().total/1000000000, 2)}GB')
			self.ui.RAM_used_info.setText(f'Used - {round(psutil.virtual_memory().used/1000000000, 2)}GB')

			if gpus != []:
				self.ui.GPU_progress.setText(f'GPU - {gpus[0].load*100}%')
				self.ui.GPU_model_info.setText(f'Model - {gpus[0].name}')
				self.ui.GPU_vram_total_info.setText(f'Total VRAM - {gpus[0].memoryTotal}')
				self.ui.GPU_vram_used_info.setText(f'Used VRAM - {gpus[0].memoryUsed}')
			else:
				self.ui.GPU_progress.setText(f'GPU - 0%')
				self.ui.GPU_model_info.setText(f'Model - Not Found')
				self.ui.GPU_vram_total_info.setText(f'Total VRAM - 0.0MB')
				self.ui.GPU_vram_used_info.setText(f'Used VRAM - 0.0MB')

		else:
			self.ui.CPU_info.setText(f"РњРѕРґРµР»СЊ - {self.get_cpu_name()}")
			self.ui.Physical_cores_info.setText(f'Р¤РёР·РёС‡РµСЃРєРёРµ СЏРґСЂР° - {psutil.cpu_count(logical=True)}')
			self.ui.Frequency_info.setText(f'Р§Р°СЃС‚РѕС‚Р° - {psutil.cpu_freq().current:.2f}MHz')

			self.ui.RAM_total_info.setText(f'РћР±С‰Р°СЏ - {round(psutil.virtual_memory().total / 1000000000, 2)}GB')
			self.ui.RAM_used_info.setText(f'Р�СЃРїРѕР»СЊР·РѕРІР°РЅРЅР°СЏ - {round(psutil.virtual_memory().used / 1000000000, 2)}GB')

			if gpus != []:
				self.ui.GPU_progress.setText(f'GPU - {gpus[0].load * 100}%')
				self.ui.GPU_model_info.setText(f'РњРѕРґРµР»СЊ - {gpus[0].name}')
				self.ui.GPU_vram_total_info.setText(f'РћР±С‰Р°СЏ VRAM - {gpus[0].memoryTotal}')
				self.ui.GPU_vram_used_info.setText(f'Р�СЃРїРѕР»СЊР·РѕРІР°РЅРЅР°СЏ VRAM - {gpus[0].memoryUsed}')
			else:
				self.ui.GPU_progress.setText(f'GPU - 0%')
				self.ui.GPU_model_info.setText(f'РњРѕРґРµР»СЊ - Not Found')
				self.ui.GPU_vram_total_info.setText(f'РћР±С‰Р°СЏ VRAM - 0.0MB')
				self.ui.GPU_vram_used_info.setText(f'Р�СЃРїРѕР»СЊР·РѕРІР°РЅРЅР°СЏ VRAM - 0.0MB')


	##==> SCAN PAGE WIDGETS SETTINGS
	####################################################
	def scanning_page_widgets_settings(self):
		self.progress_bar_scan = CicularProgress()
		self.progress_bar_scan.value = 0
		self.ui.scanning_progress_bar_widget.addWidget(self.progress_bar_scan)

		# Label а№ЃаёЄаё”аё‡а№„аёџаёҐа№Њаё—аёµа№€аёЃаёіаёҐаё±аё‡аёЄа№ЃаёЃаё™аё­аёўаё№а№€ (а№ѓаё•а№‰аё›аёёа№€аёЎ SCAN)
		self.scan_file_label = QLabel(self.ui.scanning_main_menu)
		self.scan_file_label.setGeometry(QRect(30, 338, 480, 18))
		self.scan_file_label.setStyleSheet(
			"color: #AAAAAA; font-size: 10px; font-family: 'Segoe UI'; background: transparent;"
		)
		self.scan_file_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
		self.scan_file_label.setText("")
		self.scan_file_label.show()

		self.scan_scanned_label = QLabel(self.ui.scanning_main_menu)
		self.scan_scanned_label.setGeometry(QRect(510, 10, 105, 34))
		self.scan_scanned_label.setStyleSheet("""
			QLabel {
				color: #FFFFFF;
				background-color: #2C2C2C;
				border: none;
				border-radius: 10px;
				font: 700 10pt "Segoe UI";
			}
		""")
		self.scan_scanned_label.setAlignment(Qt.AlignCenter)
		self.scan_scanned_label.setText("SCANNED\n0")
		self.scan_scanned_label.show()

		self.scan_suspicious_label = QLabel(self.ui.scanning_main_menu)
		self.scan_suspicious_label.setGeometry(QRect(622, 10, 105, 34))
		self.scan_suspicious_label.setStyleSheet("""
			QLabel {
				color: #FFAA33;
				background-color: #2C2C2C;
				border: none;
				border-radius: 10px;
				font: 700 9pt "Segoe UI";
			}
		""")
		self.scan_suspicious_label.setAlignment(Qt.AlignCenter)
		self.scan_suspicious_label.setText("SUSPICIOUS\n0")
		self.scan_suspicious_label.show()

		self.scan_detected_label = QLabel(self.ui.scanning_main_menu)
		self.scan_detected_label.setGeometry(QRect(735, 10, 105, 34))
		self.scan_detected_label.setStyleSheet("""
			QLabel {
				color: #FF4D4D;
				background-color: #2C2C2C;
				border: none;
				border-radius: 10px;
				font: 700 10pt "Segoe UI";
			}
		""")
		self.scan_detected_label.setAlignment(Qt.AlignCenter)
		self.scan_detected_label.setText("DETECTED\n0")
		self.scan_detected_label.show()

		# аё‹а№€аё­аё™а№‚аёҐа№‚аёЃа№‰а№ЃаёҐаё°а№ЃаёЄаё”аё‡ QListWidget а№ѓаё™аёћаё·а№‰аё™аё—аёµа№€а№Ђаё”аёµаёўаё§аёЃаё±аё™
		self.ui.scanning_logo.hide()

		self.scan_file_list = QListWidget(self.ui.scanning_main_menu)
		self.scan_file_list.setGeometry(QRect(510, 50, 330, 305))
		self.scan_file_list.setStyleSheet("""
			QListWidget {
				background-color: #1E1E1E;
				color: #CCCCCC;
				font-size: 10px;
				font-family: 'Segoe UI';
				border: 1px solid #444444;
				border-radius: 6px;
			}
			QListWidget::item {
				padding: 2px 6px;
			}
			QListWidget::item:selected {
				background-color: #3A3A3A;
			}
			QScrollBar:vertical {
				background: #2C2C2C;
				width: 6px;
			}
			QScrollBar::handle:vertical {
				background: #555555;
				border-radius: 3px;
			}
		""")
		self.scan_file_list.show()

		self.ui.scanning_start_btn.clicked.connect(lambda: self.scan_btn_start())

	def scan_btn_start(self):
		self.ui.scanning_start_btn.setEnabled(False)
		print("[SCAN] Button clicked")
		full = self.ui.scanning_choose_btn_full.isChecked()
		folder = self.ui.scanning_choose_btn_folder.isChecked()
		file = self.ui.scanning_choose_btn_file.isChecked()

		if full:
			path = 'C:/'
			status = 'folder'
			print(f"[SCAN] Mode=FULL  path={path}")
		elif folder:
			path = easygui.diropenbox()
			status = 'folder'
			print(f"[SCAN] Mode=FOLDER  path={path}")
		elif file:
			path = easygui.fileopenbox(default="*.exe", filetypes = ['*.exe', '*.dll', '*.ocx', '*.sys', '*.scr', '*.drv', '*.cpl', '*.efi', '*.acm', '*.ax', '*.mui', '*.tsp'])
			status = 'file'
			print(f"[SCAN] Mode=FILE  path={path}")
		else:
			path = None
			status = None
			print("[SCAN] No mode selected")

		if path != None:
			self.progress_bar_scan.set_value(0)
			self.scan_file_list.clear()
			self.scan_file_label.setText("")
			self._scan_file_count = 0
			self._scan_detected_count = 0
			self._scan_suspicious_count = 0
			self.update_scan_stats()

			self.scan_worker = ScanWorkerThread(status, path)
			self.scan_worker.progress_updated.connect(self.progress_bar_scan.set_value)
			self.scan_worker.scan_finished.connect(self.on_scan_finished)
			self.scan_worker.error_occurred.connect(lambda msg: print(f"[SCAN ERROR] {msg}"))
			self.scan_worker.file_updated.connect(self.on_scan_file_updated)
			self.scan_worker.detection_updated.connect(self.on_scan_detection_updated)

			if status == 'file':
				self.scanning_progress_timer = QtCore.QTimer()
				self.scanning_progress_timer.timeout.connect(self.circular_progress_adding)
				self.scanning_progress_timer.start(25)

			self.scan_worker.start()

		else:
			self.ui.scanning_start_btn.setEnabled(True)

	def update_scan_stats(self):
		self.scan_scanned_label.setText(f"SCANNED\n{self._scan_file_count}")
		self.scan_suspicious_label.setText(f"SUSPICIOUS\n{self._scan_suspicious_count}")
		self.scan_detected_label.setText(f"DETECTED\n{self._scan_detected_count}")

	def on_scan_file_updated(self, file_path):
		self._scan_file_count += 1
		if self._scan_file_count % 50 == 1:
			self.update_scan_stats()
		# аё­аё±аё›а№Ђаё”аё• label аё—аёёаёЃ 100 а№„аёџаёҐа№Њ а№Ђаёћаё·а№€аё­а№„аёЎа№€а№ѓаё«а№‰ UI аёЃаёЈаё°аё•аёёаёЃ
		if self._scan_file_count % 100 == 1:
			# аё•аё±аё”а№ѓаё«а№‰аёЄаё±а№‰аё™аё–а№‰аёІ path аёўаёІаё§а№ЂаёЃаёґаё™
			display = file_path if len(file_path) <= 65 else "..." + file_path[-62:]
			self.scan_file_label.setText(f"Scanning: {display}")
			# а№Ђаёћаёґа№€аёЎаёҐаё‡ list а№ЃаёҐаё° scroll аёҐаё‡аёҐа№€аёІаё‡аёЄаёёаё”
			self.scan_file_list.addItem(file_path)
			self.scan_file_list.scrollToBottom()

	def on_scan_detection_updated(self, file_path, method, details):
		if method.startswith("SUSPICIOUS:"):
			self._scan_suspicious_count += 1
		else:
			self._scan_detected_count += 1
		self.update_scan_stats()
		prefix = "SUSPICIOUS" if method.startswith("SUSPICIOUS:") else "FOUND"
		item = QListWidgetItem(f"[{prefix}:{method}] {file_path}")
		item.setToolTip(details)
		if method.startswith("HIGH:"):
			item.setForeground(QColor("#FF3333"))
		elif method.startswith("MEDIUM:") or method.startswith("SUSPICIOUS:"):
			item.setForeground(QColor("#FFAA33"))
		elif "Suspicious" in method:
			item.setForeground(QColor("#FFD966"))
		else:
			item.setForeground(QColor("#FF6B6B"))
		self.scan_file_list.addItem(item)
		self.scan_file_list.scrollToBottom()

	def on_scan_finished(self):
		self.ui.scanning_start_btn.setEnabled(True)
		self.update_scan_stats()
		self.scan_file_label.setText(f"Done - {self._scan_file_count} files scanned, {self._scan_detected_count} detected, {self._scan_suspicious_count} suspicious")
		if hasattr(self, 'scanning_progress_timer') and self.scanning_progress_timer.isActive():
			self.scanning_progress_timer.stop()
			self.progress_bar_scan.set_value(100)



	def circular_progress_adding(self):
		self.progress_bar_scan.set_value(self.progress_bar_scan.value + 1)

		if self.progress_bar_scan.value == 100:
			self.scanning_progress_timer.stop()
			self.ui.scanning_start_btn.setEnabled(True)


	##==> STORAGE PAGE WIDGETS SETTINGS
	####################################################
	def virus_storage_page_widgets_settings(self):
		self.ui.virus_storage_table.setColumnWidth(0, 135)
		self.ui.virus_storage_table.setColumnWidth(1, 87)
		self.ui.virus_storage_table.setColumnWidth(2, 480)
		self.ui.virus_storage_table.setColumnWidth(3, 40)
		self.ui.virus_storage_table.setColumnWidth(4, 40)
		self.ui.virus_storage_table.setColumnWidth(5, 40)

		self.virus_storage_update_info('start_update')

		self.virus_storage_timer_update = QTimer(self)
		self.virus_storage_timer_update.timeout.connect(lambda: self.virus_storage_update_info('constant_update'))
		self.virus_storage_timer_update.start(1000)

	def virus_storage_update_info(self, state):

		with DB() as db:
			data_from_sql = db.get_virus_storage_info()

		if state == 'start_update':
			self.ui.virus_storage_table.clear()
			self.ui.virus_storage_table.setRowCount(0)

			for i in data_from_sql:
				self.virus_storage_table_add(i[1], i[0], i[2], i[3])

		elif state == 'constant_update':
			# РЎР‘РћР  Р�РќР¤РћР РњРђР¦Р�Р� Р�Р— РўРђР‘Р›Р�Р¦Р«
			rows = self.ui.virus_storage_table.rowCount()
			data_from_table = []
			for row in range(rows):
				tmp = []
				tmp.append(self.ui.virus_storage_table.item(row, 0).text())
				tmp.append(self.ui.virus_storage_table.item(row, 2).text())
				data_from_table.append(tmp)

			data_from_sql_for_compare = [[i[0], i[1]] for i in data_from_sql]
			if data_from_table != data_from_sql_for_compare:
				self.ui.virus_storage_table.clear()
				self.ui.virus_storage_table.setRowCount(0)

				for i in data_from_sql:
					self.virus_storage_table_add(i[1], i[0], i[2], i[3])

	def virus_storage_table_add(self, path, date=None, method='Malware', details=None):

		close_btn = QPushButton()
		close_btn.clicked.connect(self.virus_storage_table_close_btn)
		close_btn.setStyleSheet("background: none;")
		icon_btn_close = QIcon()
		icon_btn_close.addFile(u":/general/imgs/general/close.png", QSize(18, 18), QIcon.Normal, QIcon.Off)
		close_btn.setIcon(icon_btn_close)
		close_btn.setMaximumSize(QSize(30, 30))

		delete_btn = QPushButton()
		delete_btn.clicked.connect(self.virus_storage_table_delete_btn)
		delete_btn.setStyleSheet("background: none;")
		icon_btn_del = QIcon()
		icon_btn_del.addFile(u":/general/imgs/general/trash.png", QSize(18, 18), QIcon.Normal, QIcon.Off)
		delete_btn.setIcon(icon_btn_del)
		delete_btn.setMaximumSize(QSize(30, 30))

		copy_btn = QPushButton()
		copy_btn.clicked.connect(self.virus_storage_table_copy_btn)
		copy_btn.setStyleSheet("background: none;")
		icon_btn_copy = QIcon()
		icon_btn_copy.addFile(u":/general/imgs/general/copy.png", QSize(18, 18), QIcon.Normal, QIcon.Off)
		copy_btn.setIcon(icon_btn_copy)
		copy_btn.setMaximumSize(QSize(30, 30))

		rowPosition = self.ui.virus_storage_table.rowCount()
		self.ui.virus_storage_table.insertRow(rowPosition)
		self.ui.virus_storage_table.setRowHeight(rowPosition, 30)

		if date == None:
			date = datetime.datetime.now()
			date = date.strftime("%d-%m-%Y %H:%M")

		self.ui.virus_storage_table.setItem(rowPosition, 0, QtWidgets.QTableWidgetItem(str(date)))
		self.ui.virus_storage_table.setItem(rowPosition, 1, QtWidgets.QTableWidgetItem(f'|  {method} - '))
		self.ui.virus_storage_table.setItem(rowPosition, 2,QtWidgets.QTableWidgetItem(path))
		if method.startswith("HIGH:"):
			self.ui.virus_storage_table.item(rowPosition, 1).setForeground(QColor("#FF3333"))
		elif method.startswith("MEDIUM:"):
			self.ui.virus_storage_table.item(rowPosition, 1).setForeground(QColor("#FFAA33"))
		if details:
			self.ui.virus_storage_table.item(rowPosition, 1).setToolTip(details)
			self.ui.virus_storage_table.item(rowPosition, 2).setToolTip(details)
		self.ui.virus_storage_table.setCellWidget(rowPosition, 3, copy_btn)
		self.ui.virus_storage_table.setCellWidget(rowPosition, 4, delete_btn)
		self.ui.virus_storage_table.setCellWidget(rowPosition, 5, close_btn)

		with DB() as db:
			db.add_virus_storage_info([(path, method, details)], date)

	def virus_storage_table_close_btn(self):
		button = self.sender()
		row = self.ui.virus_storage_table.indexAt(button.pos()).row()
		path = self.ui.virus_storage_table.item(row, 2).text()
		self.ui.virus_storage_table.removeRow(row)
		with DB() as db:
			db.delete_virus_storage_info(path)

	def virus_storage_table_delete_btn(self):
		button = self.sender()
		row = self.ui.virus_storage_table.indexAt(button.pos()).row()
		path = self.ui.virus_storage_table.item(row, 2).text()

		if os.path.exists(path):
			os.remove(path)
			self.ui.virus_storage_table.removeRow(row)
		else:
			self.ui.virus_storage_table.removeRow(row)

		with DB() as db:
			db.delete_virus_storage_info(path)

	def virus_storage_table_copy_btn(self):
		button = self.sender()
		row = self.ui.virus_storage_table.indexAt(button.pos()).row()
		pyperclip.copy(self.ui.virus_storage_table.item(row, 2).text())





	##==> FAQ PAGE WIDGETS SETTINGS
	####################################################
	def faq_page_widgets_settings(self):

		with DB() as db:
			lang = db.get_programm_settings('Language')[0]

		if lang == 1:
			self.ui.faq_small_description_btn.clicked.connect(lambda: self.open_dropdown_menu_animation(self.ui.faq_small_description_btn,self.ui.faq_small_description_white_background, 34, 105))

			self.ui.faq_home_page_btn.clicked.connect(lambda: self.open_dropdown_menu_animation(self.ui.faq_home_page_btn, self.ui.faq_home_page_white_background, 34, 90))
			self.ui.faq_scan_page_btn.clicked.connect(lambda: self.open_dropdown_menu_animation(self.ui.faq_scan_page_btn, self.ui.faq_scan_page_white_background, 34, 175))
			self.ui.faq_virus_storage_page_btn.clicked.connect(lambda: self.open_dropdown_menu_animation(self.ui.faq_virus_storage_page_btn, self.ui.faq_virus_storage_page_white_background, 34, 155))
			self.ui.faq_faq_page_btn.clicked.connect(lambda: self.open_dropdown_menu_animation(self.ui.faq_faq_page_btn, self.ui.faq_faq_page_white_background,34, 90))
			self.ui.faq_settings_page_btn.clicked.connect(lambda: self.open_dropdown_menu_animation(self.ui.faq_settings_page_btn, self.ui.faq_settings_page_white_background, 34, 70))

			self.ui.faq_authors_btn.clicked.connect(lambda: self.open_dropdown_menu_animation(self.ui.faq_authors_btn, self.ui.faq_authors_white_background,34, 125))

		else:
			self.ui.faq_small_description_btn.clicked.connect(lambda: self.open_dropdown_menu_animation(self.ui.faq_small_description_btn, self.ui.faq_small_description_white_background, 34, 119))

			self.ui.faq_home_page_btn.clicked.connect(lambda: self.open_dropdown_menu_animation(self.ui.faq_home_page_btn, self.ui.faq_home_page_white_background, 34,90))
			self.ui.faq_scan_page_btn.clicked.connect(lambda: self.open_dropdown_menu_animation(self.ui.faq_scan_page_btn, self.ui.faq_scan_page_white_background,34, 190))
			self.ui.faq_virus_storage_page_btn.clicked.connect(lambda: self.open_dropdown_menu_animation(self.ui.faq_virus_storage_page_btn, self.ui.faq_virus_storage_page_white_background,34, 155))
			self.ui.faq_faq_page_btn.clicked.connect(lambda: self.open_dropdown_menu_animation(self.ui.faq_faq_page_btn, self.ui.faq_faq_page_white_background,34, 105))
			self.ui.faq_settings_page_btn.clicked.connect(lambda: self.open_dropdown_menu_animation(self.ui.faq_settings_page_btn, self.ui.faq_settings_page_white_background,34, 90))

			self.ui.faq_authors_btn.clicked.connect(lambda: self.open_dropdown_menu_animation(self.ui.faq_authors_btn, self.ui.faq_authors_white_background, 34, 125))

		self.close_all_dropdown_menus()




	##==> SETTINGS PAGE WIDGETS SETTINGS
	####################################################
	def settings_page_widgets_settings(self):

		## ==> DROPDOWN MENU BTNS
		##############################################################
		self.ui.settings_lang_btn.clicked.connect(lambda: self.open_dropdown_menu_animation(self.ui.settings_lang_btn, self.ui.settings_lang_white, 35, 95))

		## ==> LANGUAGE
		##############################################################
		self.ui.settings_lang_eng_frame.installEventFilter(self)
		self.ui.settings_lang_rus_frame.installEventFilter(self)

		with DB() as db:
			status = bool(db.get_programm_settings('Language')[0])

		if status == False:
			self.ui.settings_lang_eng_icon.hide()
			self.ui.settings_lang_title.setText(f'РЇР·С‹Рє: Р СѓСЃСЃРєРёР№')
			self.change_lang_rus()

		elif status == True:
			self.ui.settings_lang_rus_icon.hide()
			self.ui.settings_lang_title.setText(f'Language: English')

		self.settings_import_hash_btn = QPushButton(self.ui.settings_scroll_area_frame)
		self.settings_import_hash_btn.setGeometry(QRect(0, 105, 464, 36))
		self.settings_import_hash_btn.setText("Import offline malware hashes")
		self.settings_import_hash_btn.setStyleSheet("""
			QPushButton {
				background-color: #2C2C2C;
				color: #FFFFFF;
				border: 1px solid #444444;
				border-radius: 6px;
				font: 700 11pt "Segoe UI";
			}
			QPushButton:hover {
				background-color: #383838;
				border-color: #A970FF;
			}
		""")
		self.settings_import_hash_btn.clicked.connect(self.import_hash_database)
		self.settings_import_hash_btn.show()

		self.settings_import_allowlist_btn = QPushButton(self.ui.settings_scroll_area_frame)
		self.settings_import_allowlist_btn.setGeometry(QRect(0, 145, 464, 36))
		self.settings_import_allowlist_btn.setText("Import trusted allowlist hashes")
		self.settings_import_allowlist_btn.setStyleSheet(self.settings_import_hash_btn.styleSheet())
		self.settings_import_allowlist_btn.clicked.connect(self.import_allowlist_database)
		self.settings_import_allowlist_btn.show()

		self.settings_reload_yara_btn = QPushButton(self.ui.settings_scroll_area_frame)
		self.settings_reload_yara_btn.setGeometry(QRect(0, 185, 464, 36))
		self.settings_reload_yara_btn.setText("Reload offline YARA rules on next scan")
		self.settings_reload_yara_btn.setStyleSheet(self.settings_import_hash_btn.styleSheet())
		self.settings_reload_yara_btn.clicked.connect(lambda: self.settings_hash_status_label.setText("YARA rules reload automatically on every scan"))
		self.settings_reload_yara_btn.show()

		self.settings_hash_status_label = QLabel(self.ui.settings_scroll_area_frame)
		self.settings_hash_status_label.setGeometry(QRect(0, 225, 464, 24))
		self.settings_hash_status_label.setStyleSheet("color: #AAAAAA; font-size: 10px; background: transparent;")
		self.settings_hash_status_label.setText("Supports CSV/TXT SHA256 hashes and allowlists")
		self.settings_hash_status_label.show()

	def import_hash_database(self):
		file_path = easygui.fileopenbox(
			default="*.csv",
			filetypes=['*.csv', '*.txt']
		)
		if not file_path:
			return

		with DB() as db:
			imported = db.import_hashes_from_file(file_path, source=os.path.basename(file_path))

		self.settings_hash_status_label.setText(f"Imported {imported} malware hashes")

	def import_allowlist_database(self):
		file_path = easygui.fileopenbox(
			default="*.csv",
			filetypes=['*.csv', '*.txt']
		)
		if not file_path:
			return

		with DB() as db:
			imported = db.import_allowlist_from_file(file_path, source=os.path.basename(file_path))

		self.settings_hash_status_label.setText(f"Imported {imported} trusted allowlist hashes")





	##==> ANIMATIONS
	####################################################
	def open_dropdown_menu_animation(self, button, object, standart_h, end_h):
		current_h = object.minimumHeight()

		if current_h == standart_h:
			animation = QPropertyAnimation(object, b"maximumHeight")
			animation.setDuration(100)
			animation.setEndValue(end_h)

			animation1 = QPropertyAnimation(object, b"minimumHeight")
			animation1.setDuration(100)
			animation1.setEndValue(end_h)

			up_arrow_icon = QIcon()
			up_arrow_icon.addFile(u":/general/imgs/general/up_arrow.png", QSize(), QIcon.Normal, QIcon.Off)
			button.setIcon(up_arrow_icon)

			group = QParallelAnimationGroup(self)
			group.addAnimation(animation)
			group.addAnimation(animation1)
			group.start()

		elif current_h == end_h:
			animation = QPropertyAnimation(object, b"maximumHeight")
			animation.setDuration(100)
			animation.setEndValue(standart_h)

			animation1 = QPropertyAnimation(object, b"minimumHeight")
			animation1.setDuration(100)
			animation1.setEndValue(standart_h)

			down_arrow_icon = QIcon()
			down_arrow_icon.addFile(u":/general/imgs/general/down_arrow.png", QSize(), QIcon.Normal, QIcon.Off)
			button.setIcon(down_arrow_icon)

			group = QParallelAnimationGroup(self)
			group.addAnimation(animation)
			group.addAnimation(animation1)
			group.start()

	def close_all_dropdown_menus(self):

		faq_list = [
			(self.ui.faq_small_description_white_background, self.ui.faq_small_description_btn),
			(self.ui.faq_home_page_white_background, self.ui.faq_home_page_btn),
			(self.ui.faq_scan_page_white_background, self.ui.faq_scan_page_btn),
			(self.ui.faq_virus_storage_page_white_background, self.ui.faq_virus_storage_page_btn),
			(self.ui.faq_faq_page_white_background, self.ui.faq_faq_page_btn),
			(self.ui.faq_settings_page_white_background, self.ui.faq_settings_page_btn),
			(self.ui.faq_authors_white_background, self.ui.faq_authors_btn)
		]

		for element in faq_list:
			element[0].setMinimumSize(470, 34)
			element[0].setMaximumSize(470, 34)
			down_arrow_icon = QIcon()
			down_arrow_icon.addFile(u":/general/imgs/general/down_arrow.png", QSize(), QIcon.Normal, QIcon.Off)
			element[1].setIcon(down_arrow_icon)



	##==> EVENT FILTER
	###########################################################
	def eventFilter(self, obj, e):
		try:

			## ==> BOTTOM_MENU_WHEEL_EVENT
			###########################################################
			if obj == self.ui.bottom_menu_scroll_area and e.type() == 31:
				self.ui.bottom_menu_scroll_area.horizontalScrollBar().wheelEvent(e)


			## ==> PAGE SWITCHING
			###########################################################
			elif obj == self.ui.bottom_menu_home and e.type() == 2: self.ui.Pages.setCurrentWidget(self.ui.HomePage)
			elif obj == self.ui.bottom_menu_scanning and e.type() == 2: self.ui.Pages.setCurrentWidget(self.ui.ScanningPage)
			elif obj == self.ui.bottom_menu_virus_storage and e.type() == 2: self.ui.Pages.setCurrentWidget(self.ui.VirusStoragePage)
			elif obj == self.ui.bottom_menu_faq and e.type() == 2: self.ui.Pages.setCurrentWidget(self.ui.FaqPage)
			elif obj == self.ui.bottom_menu_settings and e.type() == 2: self.ui.Pages.setCurrentWidget(self.ui.SettingsPage)


			## ==> LANGUAGES CHOOSING
			###########################################################
			elif obj == self.ui.settings_lang_rus_frame and e.type() == 2:
				with DB() as db: db.update_programm_settings("Language", False)
				self.ui.settings_lang_title.setText('РЇР·С‹Рє: Р СѓСЃСЃРєРёР№')
				self.ui.settings_lang_eng_icon.hide()
				self.ui.settings_lang_rus_icon.show()
				self.change_lang_rus()


			elif obj == self.ui.settings_lang_eng_frame and e.type() == 2:
				with DB() as db: db.update_programm_settings("Language", True)
				self.ui.settings_lang_title.setText('Language: English')
				self.ui.settings_lang_rus_icon.hide()
				self.ui.settings_lang_eng_icon.show()
				self.change_lang_eng()



			## ==> SECRET WAYS
			###########################################################
			elif (obj == self.ui.home_secret_way or obj == self.ui.scanning_secret_way or obj == self.ui.faq_secret_way or obj == self.ui.settings_secret_way) and e.type() == 2:

				with DB() as db:
					lang = bool(db.get_programm_settings('Language')[0])

				if lang == False:
					self.notify = Notify(text="<b>РЇ Р»СЋР±Р»СЋ РІР°С€ РєРѕРјРїСЊСЋС‚РµСЂ Рё РґР°РЅРЅС‹Рµ С…СЂР°РЅСЏС‰РёРµСЃСЏ РЅР° РЅРµРј :3</b>")

				elif lang == True:
					self.notify = Notify(text="<b>I Love your computer and the data stored on it :3</b>")




		except Exception as er: print(er)
		return super(QMainWindow, self).eventFilter(obj, e)


	##==> MOVING THE PROGRAM
	####################################################
	def moveWindow(self, event):
		if event.buttons() == Qt.LeftButton:
			self.move(self.pos() + event.globalPos() - self.dragPos)
			self.dragPos = event.globalPos()
			event.accept()

	def mousePressEvent(self, event):
		self.dragPos = event.globalPos()


	##==> CHANGE LANG
	####################################################
	def change_lang_rus(self):

		##==> РЎРўР РђРќР�Р¦Рђ РЎРљРђРќР�Р РћР’РђРќР�РЇ
		####################################################
		self.ui.scanning_choose_btn_full.setText("РџРѕР»РЅР°СЏ")
		self.ui.scanning_choose_btn_folder.setText("РџР°РїРєР°")
		self.ui.scanning_choose_btn_file.setText("Р¤Р°Р№Р»")
		self.ui.scanning_start_btn.setText("РЎРљРђРќР�Р РћР’РђРўР¬")

		self.ui.scanning_choose_btn_full.setStyleSheet(self.ui.scanning_choose_btn_full.styleSheet().replace('width: 35px;', 'width: 23px;'))
		self.ui.scanning_choose_btn_folder.setStyleSheet(self.ui.scanning_choose_btn_folder.styleSheet().replace('width: 22px;', 'width: 28px;'))
		self.ui.scanning_choose_btn_file.setStyleSheet(self.ui.scanning_choose_btn_file.styleSheet().replace('width: 37px;', 'width: 32px;'))



		##==> РЎРўР РђРќР�Р¦Рђ FAQ
		####################################################
		self.ui.faq_small_description_title.setText("РњР°Р»РµРЅСЊРєРѕРµ РѕРїРёСЃР°РЅРёРµ")
		self.ui.faq_small_description_text.setText("<html><head/><body><p>Spectrum Security - СЌС‚Рѕ РЅР°С‡РёРЅР°СЋС‰РёР№ РїСЂРѕРµРєС‚, РєРѕС‚РѕСЂС‹Р№ Р±С‹СЃС‚СЂРѕ РЅР°Р±РёСЂР°РµС‚ РѕР±РѕСЂРѕС‚С‹.  РЈ РЅР°СЃ РµСЃС‚СЊ РґРѕРІРѕР»СЊРЅРѕ Р±РѕР»СЊС€Р°СЏ Р±Р°Р·Р° РґР°РЅРЅС‹С… РІРёСЂСѓСЃРѕРІ, РІ РєРѕР»РёС‡РµСЃС‚РІРµ 30 РјРёР»Р»РёРѕРЅРѕРІ, Р° С‚Р°РєР¶Рµ РЅР°С€ СЃРѕР±СЃС‚РІРµРЅРЅС‹Р№ РёСЃРєСѓСЃСЃС‚РІРµРЅРЅС‹Р№ РёРЅС‚РµР»Р»РµРєС‚, РєРѕС‚РѕСЂС‹Р№ РјРѕР¶РµС‚ РѕР±РЅР°СЂСѓР¶РёС‚СЊ Р»СЋР±РѕРµ РІСЂРµРґРѕРЅРѕСЃРЅРѕРµ РџРћ.</p></body></html>")

		self.ui.faq_home_page_title.setText("Р”РѕРјР°С€РЅСЏСЏ СЃС‚СЂР°РЅРёС†Р°")
		self.ui.faq_home_page_text.setText("<html><head/><body><p>Р”РѕРјР°С€РЅСЏСЏ СЃС‚СЂР°РЅРёС†Р°, РёР»Рё Р¶Рµ Р“Р»Р°РІРЅР°СЏ СЃС‚СЂР°РЅРёС†Р°, РѕС‚РІРµС‡Р°РµС‚ Р·Р° РІС‹РІРѕРґ РёРЅС„РѕСЂРјР°С†РёРё Рѕ РЅР°РіСЂСѓР·РєРµ РІР°С€РµРіРѕ РџРљ. Р’ РЅРµР№ РїСЂРµРґСЃС‚Р°РІР»РµРЅС‹ СЃР°РјС‹Рµ РіР»Р°РІРЅС‹Рµ РїР°СЂР°РјРµС‚СЂС‹, Р° РёРјРµРЅРЅРѕ РЅР°РіСЂСѓР·РєР° CPU, RAM Рё GPU.</p></body></html>")

		self.ui.faq_scan_page_title.setText("РЎРєР°РЅРёСЂРѕРІР°РЅРёРµ")
		self.ui.faq_scan_page_text.setText("<html><head/><body><p>Р’ РІРєР»Р°РґРєРµ СЃРєР°РЅРёСЂРѕРІР°РЅРёСЏ СЃРІРµСЂС…Сѓ РЅР°СЃ РІСЃС‚СЂРµС‡Р°РµС‚ РЅРµР±РѕР»СЊС€РѕРµ РјРµРЅСЋ, СЃРѕСЃС‚РѕСЏС‰РµРµ РёР· 3 РєРЅРѕРїРѕРє: РџРѕР»РЅР°СЏ, РџР°РїРєР° Рё Р¤Р°Р№Р». РћРЅРѕ РѕС‚РІРµС‡Р°РµС‚ Р·Р° РІС‹Р±РѕСЂ СЂРµР¶РёРјР° СЃРєР°РЅРёСЂРѕРІР°РЅРёСЏ. РџРѕР»РЅР°СЏ - РїСЂРѕРІРµСЂРєР° РІСЃРµРіРѕ РІР°С€РµРіРѕ РєРѕРјРїСЊСЋС‚РµСЂР° РЅР° РЅР°Р»РёС‡РёРµ РІРёСЂСѓСЃРѕРІ. РџР°РїРєР° - РїСЂРѕРІРµСЂРєР° РІС‹Р±СЂР°РЅРЅРѕР№ РІР°РјРё РїР°РїРєРё. Р¤Р°Р№Р» - РїСЂРѕРІРµСЂРєР° РІС‹Р±СЂР°РЅРЅРѕРіРѕ РІР°РјРё С„Р°Р№Р»Р°. Р§СѓС‚СЊ РЅРёР¶Рµ РґР°РЅРЅРѕРіРѕ РјРµРЅСЋ РЅР°С…РѕРґРёС‚СЃСЏ РєСЂСѓРіРѕРІРѕР№ РёРЅРґРёРєР°С‚РѕСЂ РІС‹РїРѕР»РЅРµРЅРёСЏ РїСЂРѕС†РµСЃСЃР° СЃРєР°РЅРёСЂРѕРІР°РЅРёСЏ. Р’ СЃР°РјРѕРј РЅРёР·Сѓ СЂР°СЃРїРѕР»РѕР¶РµРЅР° РєРЅРѕРїРєР° \"РЎРєР°РЅРёСЂРѕРІР°С‚СЊ\" РїРѕСЃР»Рµ РЅР°Р¶Р°С‚РёСЏ РЅР° РєРѕС‚РѕСЂСѓСЋ Р±СѓРґРµС‚ РїСЂРѕРёР·РІРµРґРµРЅРѕ СЃРєР°РЅРёСЂРѕРІР°РЅРёРµ РІ РІС‹Р±СЂР°РЅРЅРѕРј РІР°РјРё СЂРµР¶РёРјРµ.</p></body></html>")

		self.ui.faq_virus_storage_page_title.setText("РҐСЂР°РЅРёР»РёС‰Рµ РІРёСЂСѓСЃРѕРІ")
		self.ui.faq_virus_storage_page_text.setText("<html><head/><body><p>Р’РєР»Р°РґРєР° РҐСЂР°РЅРёР»РёС‰Рµ РѕС‚РІРµС‡Р°РµС‚ Р·Р° С…СЂР°РЅРµРЅРёРµ Рё РІР·Р°РёРјРѕРґРµР№СЃС‚РІРёРµ СЃ РЅР°Р№РґРµРЅРЅС‹РјРё РІРёСЂСѓСЃР°РјРё. Р’ СЃС‚СЂРѕРєРµ СЃ РЅР°Р№РґРµРЅРЅРѕР№  СѓРіСЂРѕР·РѕР№ Р±СѓРґРµС‚ РїСЂРµРґСЃС‚Р°РІР»РµРЅР° РёРЅС„РѕСЂРјР°С†РёСЏ: РґР°С‚Р° СЃРєР°РЅРёСЂРѕРІР°РЅРёСЏ, С‚РёРї СѓРіСЂРѕР·С‹ Рё РїСѓС‚СЊ РґРѕ РІСЂРµРґРѕРЅРѕСЃРЅРѕРіРѕ С„Р°Р№Р»Р°. РўР°Рє Р¶Рµ РїСЂРёСЃСѓС‚СЃС‚РІСѓСЋС‚ С‚СЂРё РєРЅРѕРїРєРё, РїРµСЂРІР°СЏ РѕС‚РІРµС‡Р°РµС‚ Р·Р° РєРѕРїРёСЂРѕРІР°РЅРёРµ РїСѓС‚Рё Рє С„Р°Р№Р»Сѓ, РІС‚РѕСЂР°СЏ Р·Р° СѓРґР°Р»РµРЅРёРµ Р·Р°СЂР°Р¶РµРЅРЅРѕРіРѕ С„Р°Р№Р»Р°, Р° С‚СЂРµС‚СЊСЏ Р·Р° СѓР±РёСЂР°РЅРёРµ РµРіРѕ РёР· СЃРїРёСЃРєР° РЅР°Р№РґРµРЅРЅС‹С… СѓРіСЂРѕР·.</p></body></html>")

		self.ui.faq_faq_page_title.setText("РЎС‚СЂР°РЅРёС†Р° FAQ")
		self.ui.faq_faq_page_text.setText("<html><head/><body><p>Р’ РІРєР»Р°РґРєРµ FAQ, РІ РєРѕС‚РѕСЂРѕР№ РІС‹ СЃРѕР±СЃС‚РІРµРЅРЅРѕ СЃРµР№С‡Р°СЃ Рё РЅР°С…РѕРґРёС‚РµСЃСЊ, РїСЂРµРґСЃС‚Р°РІР»РµРЅС‹ СЂР°Р·Р»РёС‡РЅС‹Рµ РёРЅСЃС‚СЂСѓРєС†РёРё Рё РѕС‚РІРµС‚С‹ РЅР° РёРЅС‚РµСЂРµСЃСѓСЋС‰РёРµ РІР°СЃ РІРѕРїСЂРѕСЃС‹. Р’ РїСЂРѕС†РµСЃСЃРµ РѕР±РЅРѕРІР»РµРЅРёР№ Р±РёР±Р»РёРѕС‚РµРєР° FAQ Р±СѓРґРµС‚ СЃС‚СЂРµРјРёС‚РµР»СЊРЅРѕ СЂР°СЃС€РёСЂСЏС‚СЊСЃСЏ.</p></body></html>")

		self.ui.faq_settings_page_title.setText("РќР°СЃС‚СЂРѕР№РєРё")
		self.ui.faq_settings_page_text.setText("<html><head/><body><p>Р’РєР»Р°РґРєР° РќР°СЃС‚СЂРѕР№РєРё РѕС‚РІРµС‡Р°РµС‚ Р·Р° РіРёР±РєРѕРµ РёР·РјРµРЅРµРЅРёРµ СЂР°Р·Р»РёС‡РЅС‹С… РїР°СЂР°РјРµС‚СЂРѕРІ РїСЂРѕРіСЂР°РјРјС‹, РґР»СЏ СѓР»СѓС‡С€РµРЅРёСЏ РµС‘ СЂР°Р±РѕС‚РѕСЃРїРѕСЃРѕР±РЅРѕСЃС‚Рё.</p></body></html>")

		self.ui.faq_authors_title.setText("РђРІС‚РѕСЂС‹")
		self.ui.faq_authors_text.setText("<html><head/><body><p>Р Р°Р·СЂР°Р±РѕС‚С‡РёРє - DIMFLIX</p><p>UX/UI Р”РёР·Р°Р№РЅРµСЂ Рё Р Р°Р·СЂР°Р±РѕС‚С‡РёРє - DIMFLIX </p><p>Р›РѕРіРѕС‚РёРї Рё РёРјСЏ РєРѕРјРїР°РЅРёРё - PlayStack</body></html>")

		self.faq_page_widgets_settings()

		##==> РќРђРЎРўР РћР™РљР�
		####################################################
		self.ui.settings_lang_rus_title.setText("Р СѓСЃСЃРєРёР№")
		self.ui.settings_lang_eng_title.setText("English")



		##==> РҐР РђРќР�Р›Р�Р©Р• Р’Р�Р РЈРЎРћР’
		####################################################
		font = QFont()
		font.setFamily(u"Segoe UI")
		font.setPointSize(10)
		font.setBold(True)
		font.setWeight(75)
		self.ui.virus_storage_main_title_label.setText("РҐР РђРќР�Р›Р�Р©Р• Р’Р�Р РЈРЎРћР’")
		self.ui.virus_storage_warning.setText("РџСЂРµРґСѓРїСЂРµР¶РґРµРЅРёРµ - Р°РЅС‚РёРІРёСЂСѓСЃ РЅР°С…РѕРґРёС‚СЃСЏ РІ СЃС‚Р°РґРёРё СЂР°Р·СЂР°Р±РѕС‚РєРё, С‡С‚Рѕ РјРѕР¶РµС‚ РїСЂРёРІРµСЃС‚Рё Рє РЅРµС‚РѕС‡РЅС‹Рј РѕРїСЂРµРґРµР»РµРЅРёСЏРј РІРёСЂСѓСЃРѕРІ.  РћРіСЂРѕРјРЅР°СЏ РїСЂРѕСЃСЊР±Р° РїСЂРѕРІРµСЂРёС‚СЊ С„Р°Р№Р» СЃР°РјРѕСЃС‚РѕСЏС‚РµР»СЊРЅРѕ, РґР°Р±С‹ РёР·Р±РµР¶Р°С‚СЊ СѓРґР°Р»РµРЅРёСЏ С†РµРЅРЅРѕР№ РёРЅС„РѕСЂРјР°С†РёРё РёР»Рё СЃРёСЃС‚РµРјРЅС‹С… С„Р°Р№Р»РѕРІ.")
		self.ui.virus_storage_warning.setFont(font)



		##==> РќР�Р–РќРЇРЇ РџРђРќР•Р›Р¬
		####################################################
		self.ui.home_title.setText("Р“Р»Р°РІРЅР°СЏ")
		self.ui.home_description.setText("РџСЂРѕСЃРјРѕС‚СЂ РїСЂРѕРёР·РІРѕРґРёС‚РµР»СЊРЅРѕСЃС‚Рё")

		self.ui.scanning_title.setText("РЎРєР°РЅРёСЂРѕРІР°РЅРёРµ")
		self.ui.scanning_description.setText("РЎРєР°РЅРёСЂРѕРІР°РЅРёРµ РџРљ РЅР° РІРёСЂСѓСЃС‹")

		self.ui.virus_storage_title.setText("РҐСЂР°РЅРёР»РёС‰Рµ")
		self.ui.virus_storage_description.setText("РҐСЂР°РЅРёР»РёС‰Рµ РЅР°Р№РґРµРЅРЅС‹С… РІРёСЂСѓСЃРѕРІ")

		self.ui.faq_title.setText("FAQ")
		self.ui.faq_description.setText("Р§Р°СЃС‚Рѕ Р·Р°РґР°РІР°РµРјС‹Рµ РІРѕРїСЂРѕСЃС‹")

		self.ui.settings_title.setText("РќР°СЃС‚СЂРѕР№РєРё")
		self.ui.settings_description.setText("РќР°СЃС‚СЂРѕР№РєРё РїСЂРѕРіСЂР°РјРјС‹")

	def change_lang_eng(self):

		##==> РЎРўР РђРќР�Р¦Рђ РЎРљРђРќР�Р РћР’РђРќР�РЇ
		####################################################
		self.ui.scanning_choose_btn_full.setText("FULL")
		self.ui.scanning_choose_btn_folder.setText("FOLDER")
		self.ui.scanning_choose_btn_file.setText("FILE")
		self.ui.scanning_start_btn.setText("SCAN")

		self.ui.scanning_choose_btn_full.setStyleSheet(self.ui.scanning_choose_btn_full.styleSheet().replace('width: 23px;', 'width: 35px;'))
		self.ui.scanning_choose_btn_folder.setStyleSheet(self.ui.scanning_choose_btn_folder.styleSheet().replace('width: 28px;', 'width: 22px;'))
		self.ui.scanning_choose_btn_file.setStyleSheet(self.ui.scanning_choose_btn_file.styleSheet().replace('width: 32px;', 'width: 37px;'))





		##==> РЎРўР РђРќР�Р¦Рђ FAQ
		####################################################
		self.ui.faq_small_description_title.setText("Small description")
		self.ui.faq_small_description_text.setText("<html><head/><body><p>Spectrum Security is a start-up project that is rapidly gaining momentum.  We have a fairly large database of viruses, in the amount of 30 million, as well as our own artificial intelligence that can detect any malware.</p></body></html>")

		self.ui.faq_home_page_title.setText("Home Page")
		self.ui.faq_home_page_text.setText("<html><head/><body><p>The Home page, or the Main page, is responsible for displaying information about the load of your PC. It presents the most important parameters, namely the CPU, RAM and GPU load.</p></body></html>")

		self.ui.faq_scan_page_title.setText("Scanning Page")
		self.ui.faq_scan_page_text.setText("<html><head/><body><p>In the scan tab on top we are greeted by a small menu consisting of 3 buttons: Full, Folder and File. It is responsible for selecting the scanning mode. Full - scan of your entire computer for viruses. Folder - checking the folder you selected. File - checking the file you selected. Just below this menu is a circular indicator of the scanning process. At the very bottom there is a &quot;Scan&quot; button, after clicking on which a scan will be performed in the mode you selected.</p></body></html>")

		self.ui.faq_virus_storage_page_title.setText("Virus Storage Page")
		self.ui.faq_virus_storage_page_text.setText("<html><head/><body><p>The Storage tab is responsible for storing and interacting with found viruses. The line with the found threat will contain information: the date of the scan, the type of threat and the path to the malicious file. There are also three buttons, the first is responsible for copying the path to the file, the second for deleting the infected file, and the third for removing it from the list of threats found.</p></body></html>")

		self.ui.faq_faq_page_title.setText("FAQ Page")
		self.ui.faq_faq_page_text.setText("<html><head/><body><p>The FAQ tab, in which you are actually now, provides various instructions and answers to your questions. In the process of updates, the FAQ library will expand rapidly.</p></body></html>")

		self.ui.faq_settings_page_title.setText("Settings Page")
		self.ui.faq_settings_page_text.setText("<html><head/><body><p>The Settings tab is responsible for flexibly changing various program parameters to improve its performance.</p></body></html>")

		self.ui.faq_authors_title.setText("Authors")
		self.ui.faq_authors_text.setText("<html><head/><body><p>Developer - DIMFLIX</p><p>UX/UI Designer and Developer - DIMFLIX </p><p>Logo and Company name- PlayStack </p></body></html>")

		self.faq_page_widgets_settings()


		##==> РҐР РђРќР�Р›Р�Р©Р• Р’Р�Р РЈРЎРћР’
		####################################################
		font = QFont()
		font.setFamily(u"Segoe UI")
		font.setPointSize(11)
		font.setBold(True)
		font.setWeight(75)
		self.ui.virus_storage_main_title_label.setText("VIRUS STORAGE")
		self.ui.virus_storage_warning.setText("<html><head/><body><p>Warning - the antivirus is under development, which may cause inaccurate virus definitions.  A huge request to check the file yourself, in order to avoid deleting valuable information or system files</p></body></html>")
		self.ui.virus_storage_warning.setFont(font)


		##==> РќР�Р–РќРЇРЇ РџРђРќР•Р›Р¬
		####################################################
		self.ui.home_title.setText("Home Page")
		self.ui.home_description.setText("PC performance monitoring")

		self.ui.scanning_title.setText("Scanning")
		self.ui.scanning_description.setText("Scan your PC for viruses")

		self.ui.virus_storage_title.setText("Virus storage")
		self.ui.virus_storage_description.setText("Storage of found viruses")

		self.ui.faq_title.setText("FAQ")
		self.ui.faq_description.setText("Frequently asked questions")

		self.ui.settings_title.setText("Settings")
		self.ui.settings_description.setText("Application Settings")











##==> NOTIFY INTERFACE CLASS
####################################################
class Notify(QMainWindow):
	def __init__(self, text):
		QMainWindow.__init__(self)
		self.ui = SpectrumSecurityNotify()
		self.ui.setupUi(self)

		## ==> MAIN SETTINGS
		##############################################################
		self.setWindowFlags(Qt.ToolTip)
		self.setWindowFlags(QtCore.Qt.Window | QtCore.Qt.CustomizeWindowHint | Qt.WindowStaysOnTopHint)
		self.setWindowFlag(QtCore.Qt.FramelessWindowHint)
		self.setAttribute(QtCore.Qt.WA_TranslucentBackground, True)

		self.ui.notify_text.setText(text)

		## ==> WINDOW BTNS
		##############################################################
		self.ui.close_btn.clicked.connect(lambda: self.close_notify())

		## ==> MOVE TO BOTTOM RIGHT
		##############################################################
		self.desktop = QGuiApplication.primaryScreen().availableGeometry()
		self.start_animation()

		self.notify = QSound('data/notifications/notification.wav', self)
		self.notify.play()

		self.show()

	def start_animation(self):
		self.start_animation = QPropertyAnimation(self, b"geometry")
		self.start_animation.setDuration(200)
		self.start_animation.setStartValue(QRect(self.desktop.width() - 1, self.desktop.height() - 110, 1, 100))
		self.start_animation.setEndValue(QRect(self.desktop.width() - 410, self.desktop.height() - 110, 400, 100))
		self.start_animation.start()
		QTimer.singleShot(5200, lambda: self.end_animation())

	def end_animation(self):
		self.end_animation = QPropertyAnimation(self, b"geometry")
		self.end_animation.setDuration(200)
		self.end_animation.setStartValue(QRect(self.desktop.width() - 410, self.desktop.height() - 110, 400, 100))
		self.end_animation.setEndValue(QRect(self.desktop.width() - 1, self.desktop.height() - 110, 1, 100))
		self.end_animation.start()
		QTimer.singleShot(200, lambda: self.close_notify())

	def close_notify(self):
		self.close()


class SystemTrayIcon(QtWidgets.QSystemTrayIcon):

	def __init__(self, icon, parent=None):
		QtWidgets.QSystemTrayIcon.__init__(self, icon, parent)
		self.setToolTip(f'Spectrum Security')
		menu = QtWidgets.QMenu(parent)

		menu.addAction(QtGui.QIcon("icons/exit.png"), "Р’С‹Р№С‚Рё", lambda: sys.exit())
		menu.addSeparator()
		self.setContextMenu(menu)
		self.activated.connect(self.onTrayIconActivated)

	def onTrayIconActivated(self, event):
		if event == self.Trigger:  # РїСЂРё РѕРґРёРЅРѕС‡РЅРѕРј РєР»РёРєРµ Р›Р•Р’РћР™ РљРќРћРџРљРћР™ РњР«РЁР� - РїРѕРєР°Р·С‹РІР°РµС‚ РњР•РќР®
			self.contextMenu().exec_(QtGui.QCursor.pos())  # РїРѕРєР°Р·С‹РІР°РµС‚ РјРµРЅСЋ РІ С‚РµРєСѓС‰РµР№ РїРѕР·РёС†РёРё РјС‹С€Рё





if __name__ == '__main__':
	app = QApplication(sys.argv)
	window = MainWindow()
	sys.exit(app.exec_())
