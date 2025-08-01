import sys
import grpc
import threading
import locale
from datetime import datetime, timedelta
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableView, QLineEdit, QPushButton, QComboBox, QLabel,
    QSplitter, QTreeWidget, QTreeWidgetItem, QHeaderView, QCheckBox
)
from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex, QTimer
from PyQt6.QtGui import QColor, QFont, QBrush

import tracer_pb2
import tracer_pb2_grpc

locale.setlocale(locale.LC_TIME, "")

# Константы
MAX_EVENTS = 10000        # Максимальное количество событий в таблице
BATCH_UPDATE_MS = 100     # Интервал обновления UI (мс)
HIGHLIGHT_NEW_EVENTS_MS = 2000  # Время подсветки новых событий (мс)

# Типы событий из заголовочного файла
EVENT_TYPES = [
    "",  # Любой тип (ANY)
    "EXECVE",
    "OPEN",
    "READ",
    "WRITE",
    "ACCEPT",
    "CONNECT",
    "CLONE",
    "EXIT",
    "TCP_CONN",
    "UPROBE"
]

def clean_str(s, max_len=200):
    """Очистка строки от непечатаемых символов с ограничением длины"""
    try:
        if isinstance(s, bytes):
            s = s.decode("utf-8", errors="replace")
        s = ''.join(c for c in s.replace('\x00', '').strip() if c.isprintable())
        return s[:max_len] + '...' if len(s) > max_len else s
    except Exception:
        return "Invalid"

class EventTableModel(QAbstractTableModel):
    COLUMNS = ["Time", "Type", "PID", "Command", "Details"]
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.events = []  # Все события (новые в начале)
        self.filtered_events = []  # Отфильтрованные события
        self.pid_filter = ""
        self.type_filter = ""
        self.search_text = ""
        self.new_events = set()  # ID новых событий для подсветки
        self.last_event_id = 0
        self.auto_clean = True  # Флаг автоочистки буфера
        
    def rowCount(self, parent=QModelIndex()):
        return len(self.filtered_events)
    
    def columnCount(self, parent=QModelIndex()):
        return len(self.COLUMNS)
    
    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
            
        row = index.row()
        col = index.column()
        
        if row >= len(self.filtered_events):
            return None
            
        event = self.filtered_events[row]
        
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:  # Time
                return event.timestamp.strftime("%H:%M:%S.%f")[:-3]
            elif col == 1:  # Type
                return event.type
            elif col == 2:  # PID
                return str(event.pid)
            elif col == 3:  # Command
                return clean_str(event.comm)
            elif col == 4:  # Details
                return clean_str(event.details)
                
        elif role == Qt.ItemDataRole.BackgroundRole:
            # Подсветка новых событий
            if event.id in self.new_events:
                return QBrush(QColor(255, 255, 200))  # Светло-желтый
                
            # Цветовая маркировка по типам событий
            if "ERROR" in event.details:
                return QBrush(QColor(255, 200, 200))
            elif "EXECVE" in event.type:
                return QBrush(QColor(230, 240, 255))
            elif "TCP_CONN" in event.type:
                return QBrush(QColor(230, 255, 230))
            elif "OPEN" in event.type:
                return QBrush(QColor(255, 230, 230))
            elif "UPROBE" in event.type:
                return QBrush(QColor(255, 230, 255))
                
        elif role == Qt.ItemDataRole.FontRole:
            # Жирный шрифт для новых событий
            if event.id in self.new_events:
                font = QFont()
                font.setBold(True)
                return font
                
        return None
    
    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.COLUMNS[section]
        return None
        
    def add_events(self, events):
        """Добавление пачки событий в начало списка"""
        if not events:
            return
            
        # Генерируем уникальные ID для новых событий
        for event in events:
            self.last_event_id += 1
            event.id = self.last_event_id
            self.new_events.add(event.id)
            
        # Вставляем новые события в начало
        self.events = events + self.events
        
        # Автоочистка буфера при выборе ANY
        if self.auto_clean and len(self.events) > MAX_EVENTS:
            self.events = self.events[:MAX_EVENTS]
            
        # Применяем фильтры
        self.apply_filters()
        
    def apply_filters(self):
        """Применение текущих фильтров"""
        self.beginResetModel()
        
        self.filtered_events = [
            e for e in self.events
            if (not self.pid_filter or str(e.pid) == self.pid_filter) and
               (not self.type_filter or e.type == self.type_filter) and
               (not self.search_text or self.search_text.lower() in clean_str(e.details).lower())
        ]
        
        # Очистка буфера для конкретного фильтра
        if not self.auto_clean and len(self.filtered_events) > MAX_EVENTS:
            self.filtered_events = self.filtered_events[:MAX_EVENTS]
        
        self.endResetModel()
        
    def set_filters(self, pid_filter, type_filter, search_text):
        """Установка новых фильтров"""
        self.pid_filter = pid_filter
        self.type_filter = type_filter
        self.search_text = search_text
        
        # Включаем автоочистку только для ANY
        self.auto_clean = (type_filter == "")
        self.apply_filters()
        
    def clear_highlight(self, event_id):
        """Удаление подсветки события"""
        if event_id in self.new_events:
            self.new_events.remove(event_id)
            # Находим индекс события для обновления
            for row, event in enumerate(self.filtered_events):
                if event.id == event_id:
                    index = self.index(row, 0)
                    self.dataChanged.emit(index, index)
                    break

class TracerUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("eBPF Tracer")
        self.setGeometry(100, 100, 1200, 800)
        
        # Центральный виджет
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Основной макет
        main_layout = QVBoxLayout(central_widget)
        
        # Панель управления
        control_layout = QHBoxLayout()
        
        # Кнопка паузы
        self.pause_button = QPushButton("⏸️ Pause")
        self.pause_button.setCheckable(True)
        self.pause_button.setStyleSheet("QPushButton:checked { background-color: #FF9999; }")
        self.pause_button.clicked.connect(self.toggle_pause)
        control_layout.addWidget(self.pause_button)
        
        # Кнопка очистки
        clear_button = QPushButton("🗑️ Clear")
        clear_button.clicked.connect(self.clear_events)
        control_layout.addWidget(clear_button)
        
        # Статус
        self.status_label = QLabel("Receiving events...")
        control_layout.addWidget(self.status_label)
        
        control_layout.addStretch()
        
        # Кнопка автоскролла
        self.auto_scroll_check = QCheckBox("Auto-scroll to new events")
        self.auto_scroll_check.setChecked(True)
        control_layout.addWidget(self.auto_scroll_check)
        
        main_layout.addLayout(control_layout)
        
        # Панель фильтров
        filter_layout = QHBoxLayout()
        
        self.pid_filter = QLineEdit()
        self.pid_filter.setPlaceholderText("Filter by PID...")
        self.pid_filter.setMaximumWidth(150)
        filter_layout.addWidget(QLabel("PID:"))
        filter_layout.addWidget(self.pid_filter)
        
        self.type_filter = QComboBox()
        self.type_filter.addItems(EVENT_TYPES)
        self.type_filter.setCurrentIndex(0)  # ANY
        self.type_filter.setMaximumWidth(150)
        filter_layout.addWidget(QLabel("Type:"))
        filter_layout.addWidget(self.type_filter)
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search in details...")
        filter_layout.addWidget(QLabel("Search:"))
        filter_layout.addWidget(self.search_box)
        
        apply_btn = QPushButton("Apply Filters")
        apply_btn.clicked.connect(self.apply_filters)
        filter_layout.addWidget(apply_btn)
        
        clear_btn = QPushButton("Clear Filters")
        clear_btn.clicked.connect(self.clear_filters)
        filter_layout.addWidget(clear_btn)
        
        main_layout.addLayout(filter_layout)
        
        # Разделитель для таблицы и деталей
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Таблица событий
        self.table_view = QTableView()
        self.model = EventTableModel()
        self.table_view.setModel(self.model)
        
        # Настройка таблицы
        self.table_view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table_view.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table_view.doubleClicked.connect(self.show_event_details)
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table_view.verticalHeader().setDefaultSectionSize(24)
        self.table_view.setSortingEnabled(True)
        
        # Настройка ширины колонок
        self.table_view.setColumnWidth(0, 120)  # Time
        self.table_view.setColumnWidth(1, 80)   # Type
        self.table_view.setColumnWidth(2, 70)   # PID
        self.table_view.setColumnWidth(3, 150)  # Command
        
        splitter.addWidget(self.table_view)
        
        # Детали события
        self.details_tree = QTreeWidget()
        self.details_tree.setHeaderLabels(["Field", "Value"])
        self.details_tree.setHeaderHidden(False)
        self.details_tree.setRootIsDecorated(False)
        splitter.addWidget(self.details_tree)
        
        splitter.setSizes([600, 200])
        main_layout.addWidget(splitter)
        
        # Статус бар
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Connecting to tracer service...")
        
        # Буфер для событий и блокировка
        self.event_buffer = []
        self.buffer_lock = threading.Lock()
        self.paused = False
        self.event_count = 0
        self.last_scroll_position = 0
        
        # Таймеры
        self.update_timer = QTimer(self)
        self.update_timer.setInterval(BATCH_UPDATE_MS)
        self.update_timer.timeout.connect(self.process_buffered_events)
        self.update_timer.start()
        
        self.highlight_timer = QTimer(self)
        self.highlight_timer.setInterval(500)
        self.highlight_timer.timeout.connect(self.update_highlights)
        self.highlight_timer.start()
        
        # Подключение к gRPC
        self.connect_grpc()
        
        # Отслеживание положения скролла
        self.table_view.verticalScrollBar().valueChanged.connect(self.track_scroll_position)
        
    def connect_grpc(self):
        try:
            self.channel = grpc.insecure_channel('localhost:50051')
            self.stub = tracer_pb2_grpc.TracerServiceStub(self.channel)
            
            threading.Thread(target=self.stream_events, daemon=True).start()
            self.status_bar.showMessage("Connected to tracer service")
        except Exception as e:
            self.status_bar.showMessage(f"Connection error: {str(e)}")
        
    def stream_events(self):
        """Поток для получения событий от gRPC сервера"""
        request = tracer_pb2.EventRequest()
        
        try:
            for pb_event in self.stub.StreamEvents(request):
                if self.paused:
                    continue
                    
                event = type('Event', (), {
                    'type': pb_event.type,
                    'pid': pb_event.pid,
                    'comm': pb_event.comm,
                    'timestamp': pb_event.timestamp.ToDatetime(),
                    'details': pb_event.details
                })
                
                # Добавляем событие в буфер (с блокировкой)
                with self.buffer_lock:
                    self.event_buffer.append(event)
                
                self.event_count += 1
                if self.event_count % 100 == 0:
                    self.status_label.setText(f"Events: {self.event_count}")
                    
        except grpc.RpcError as e:
            self.status_bar.showMessage(f"gRPC error: {e.details()}")
            
    def process_buffered_events(self):
        """Обработка накопленных событий (вызывается по таймеру)"""
        if self.paused or not self.event_buffer:
            return
            
        # Забираем события из буфера
        with self.buffer_lock:
            batch = self.event_buffer
            self.event_buffer = []
            
        # Добавляем пачку в модель (новые события вверху)
        self.model.add_events(batch)
        
        # "Умный" автоскроллинг
        if self.auto_scroll_check.isChecked():
            scroll_bar = self.table_view.verticalScrollBar()
            current_pos = scroll_bar.value()
            
            # Скроллим только если пользователь не прокручивал вниз
            if current_pos <= 10:
                self.table_view.scrollToTop()
    
    def update_highlights(self):
        """Обновление подсветки новых событий"""
        now = datetime.now()
        to_remove = []
        
        # Убираем подсветку старых событий
        for event_id in self.model.new_events:
            for event in self.model.events:
                if event.id == event_id:
                    # Проверяем, прошло ли достаточно времени
                    if (now - event.timestamp) > timedelta(milliseconds=HIGHLIGHT_NEW_EVENTS_MS):
                        to_remove.append(event_id)
                    break
        
        # Удаляем старые подсветки
        for event_id in to_remove:
            self.model.clear_highlight(event_id)
    
    def track_scroll_position(self, value):
        """Отслеживание позиции скролла для умного автоскроллинга"""
        self.last_scroll_position = value
        
    def toggle_pause(self, checked):
        """Переключение режима паузы"""
        self.paused = checked
        if checked:
            self.pause_button.setText("▶️ Resume")
            self.status_label.setText(f"PAUSED | Events: {self.event_count}")
        else:
            self.pause_button.setText("⏸️ Pause")
            self.status_label.setText(f"Receiving events... | Events: {self.event_count}")
    
    def clear_events(self):
        """Очистка всех событий"""
        self.model.beginResetModel()
        self.model.events = []
        self.model.filtered_events = []
        self.model.new_events = set()
        self.model.endResetModel()
        self.event_count = 0
        self.status_label.setText("Events cleared")
        
    def apply_filters(self):
        """Применение фильтров из UI"""
        pid_text = self.pid_filter.text().strip()
        type_text = self.type_filter.currentText()
        search_text = self.search_box.text().strip()
        
        self.model.set_filters(pid_text, type_text, search_text)
        
    def clear_filters(self):
        """Сброс всех фильтров"""
        self.pid_filter.clear()
        self.type_filter.setCurrentIndex(0)  # ANY
        self.search_box.clear()
        self.model.set_filters("", "", "")
        
    def show_event_details(self, index):
        """Показ деталей выбранного события"""
        self.details_tree.clear()
        
        if not index.isValid():
            return
            
        event = self.model.filtered_events[index.row()]
        
        details = [
            ("Type", event.type),
            ("Timestamp", event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")),
            ("PID", str(event.pid)),
            ("Command", clean_str(event.comm)),
            ("Details", clean_str(event.details))
        ]
        
        # Для UPROBE добавляем специальную обработку
        if event.type == "UPROBE":
            parts = event.details.split('|')
            if len(parts) >= 2:
                details.append(("Function", parts[0]))
                details.append(("Arguments", parts[1]))
        
        for field, value in details:
            item = QTreeWidgetItem([field, value])
            self.details_tree.addTopLevelItem(item)
            
        self.details_tree.expandAll()
        self.details_tree.resizeColumnToContents(0)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TracerUI()
    window.show()
    sys.exit(app.exec())