import sys
import grpc
import threading
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableView, QLineEdit, QPushButton, QComboBox, QLabel,
    QSplitter, QTreeWidget, QTreeWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex, QSortFilterProxyModel
from PyQt6.QtGui import QColor

import tracer_pb2
import tracer_pb2_grpc


def clean_str(s):
    try:
        if isinstance(s, bytes):
            s = s.decode("utf-8", errors="replace")
        return s.replace('\x00', '').strip()
    except Exception:
        return "Invalid"


class EventTableModel(QAbstractTableModel):
    COLUMNS = ["Time", "Type", "PID", "Command", "Details"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.events = []
        self.filtered_events = []

    def rowCount(self, parent=QModelIndex()):
        return len(self.filtered_events)

    def columnCount(self, parent=QModelIndex()):
        return len(self.COLUMNS)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()
        event = self.filtered_events[row]

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return event.timestamp.strftime("%H:%M:%S.%f")[:-3]
            elif col == 1:
                return event.type
            elif col == 2:
                return str(event.pid)
            elif col == 3:
                return event.comm
            elif col == 4:
                return event.details

        elif role == Qt.ItemDataRole.BackgroundRole:
            if "ERROR" in event.details:
                return QColor(255, 200, 200)
            elif "EXECVE" in event.type:
                return QColor(230, 240, 255)
            elif "TCP_CONN" in event.type:
                return QColor(230, 255, 230)
            elif "OPEN" in event.type:
                return QColor(255, 230, 230)

        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.COLUMNS[section]
        return None

    def add_event(self, event):
        self.beginInsertRows(QModelIndex(), len(self.events), len(self.events))
        self.events.append(event)
        self.filtered_events.append(event)
        self.endInsertRows()

    def apply_filters(self, pid_filter="", type_filter="", search_text=""):
        self.beginResetModel()
        self.filtered_events = [
            e for e in self.events
            if (not pid_filter or str(e.pid) == pid_filter) and
               (not type_filter or e.type == type_filter) and
               (not search_text or search_text.lower() in e.details.lower())
        ]
        self.endResetModel()


class TracerUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("eBPF Tracer")
        self.resize(1200, 800)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        filter_layout = QHBoxLayout()
        self.pid_filter = QLineEdit(placeholderText="Filter by PID...")
        filter_layout.addWidget(QLabel("PID:"))
        filter_layout.addWidget(self.pid_filter)

        self.type_filter = QComboBox()
        self.type_filter.addItems(["", "EXECVE", "OPEN", "TCP_CONN", "UPROBE"])
        filter_layout.addWidget(QLabel("Type:"))
        filter_layout.addWidget(self.type_filter)

        self.search_box = QLineEdit(placeholderText="Search...")
        filter_layout.addWidget(QLabel("Search:"))
        filter_layout.addWidget(self.search_box)

        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self.apply_filters)
        filter_layout.addWidget(apply_btn)

        main_layout.addLayout(filter_layout)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self.table_view = QTableView()
        self.model = EventTableModel()
        self.proxy_model = QSortFilterProxyModel()
        self.proxy_model.setSourceModel(self.model)
        self.table_view.setModel(self.proxy_model)
        self.table_view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table_view.doubleClicked.connect(self.show_event_details)

        self.table_view.horizontalHeader().setStretchLastSection(True)
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        self.details_tree = QTreeWidget()
        self.details_tree.setHeaderLabels(["Field", "Value"])

        splitter.addWidget(self.table_view)
        splitter.addWidget(self.details_tree)
        splitter.setSizes([800, 200])
        main_layout.addWidget(splitter)

        self.status_bar = self.statusBar()
        self.connect_grpc()

    def connect_grpc(self):
        self.channel = grpc.insecure_channel('localhost:50051')
        self.stub = tracer_pb2_grpc.TracerServiceStub(self.channel)

        threading.Thread(target=self.stream_events, daemon=True).start()
        self.status_bar.showMessage("Connected to tracer service")

    def stream_events(self):
        request = tracer_pb2.EventRequest()
        try:
            for pb_event in self.stub.StreamEvents(request):
                event = type('Event', (), {
                    'type': pb_event.type,
                    'pid': pb_event.pid,
                    'comm': clean_str(pb_event.comm),
                    'timestamp': pb_event.timestamp.ToDatetime(),
                    'details': clean_str(pb_event.details)
                })
                self.model.add_event(event)
        except grpc.RpcError as e:
            self.status_bar.showMessage(f"gRPC error: {e.details()}")

    def apply_filters(self):
        pid_text = self.pid_filter.text().strip()
        type_text = self.type_filter.currentText()
        search_text = self.search_box.text().strip()
        self.model.apply_filters(pid_text, type_text, search_text)

    def show_event_details(self, index):
        self.details_tree.clear()
        event = self.model.filtered_events[index.row()]

        details = [
            ("Type", event.type),
            ("Timestamp", event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")),
            ("PID", str(event.pid)),
            ("Command", event.comm),
            ("Details", event.details)
        ]

        for field, value in details:
            item = QTreeWidgetItem([field, value])
            self.details_tree.addTopLevelItem(item)

        self.details_tree.expandAll()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TracerUI()
    window.show()
    sys.exit(app.exec())
