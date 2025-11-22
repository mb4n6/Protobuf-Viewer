from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
import sys
import re

try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QFileDialog, QTableWidget, QTableWidgetItem,
        QAbstractItemView, QSplitter, QVBoxLayout, QHBoxLayout, QPushButton,
        QTextEdit, QLabel, QCheckBox, QWidget, QMessageBox, QDialog, QDialogButtonBox
    )
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QAction, QColor, QFont
except Exception as e:
    print("ERROR: PySide6 konnte nicht geladen werden:", e)
    print("Installiere mit: pip install PySide6")
    raise

HEX_RE = re.compile(r"[0-9a-fA-F]{2}")

def clean_hex(s: str) -> str:
    if not s:
        return ""
    return "".join(HEX_RE.findall(s))

def hex_to_bytes(s: str) -> bytes:
    s = clean_hex(s)
    return bytes(int(s[i:i+2], 16) for i in range(0, len(s), 2))

def bytes_to_hex(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)

def ascii_preview(b: bytes) -> str:
    return "".join(chr(x) if 32 <= x <= 126 else "." for x in b)

def is_likely_utf8(b: bytes) -> bool:
    try:
        b.decode("utf-8")
        return True
    except Exception:
        return False

def decode_utf8(b: bytes) -> str:
    try:
        return b.decode("utf-8", errors="strict")
    except Exception:
        return b.decode("utf-8", errors="ignore")

def read_varint(buf: bytes, off: int):
    x = 0
    s = 0
    i = off
    for _ in range(10):
        if i >= len(buf):
            raise EOFError("varint")
        b = buf[i]
        i += 1
        x |= (b & 0x7F) << s
        if (b & 0x80) == 0:
            break
        s += 7
    return x, i

def zigzag_decode(n: int) -> int:
    n = int(n)
    return (n >> 1) ^ (-(n & 1))

def read_fixed32(buf: bytes, off: int):
    if off + 4 > len(buf):
        raise EOFError("fixed32")
    import struct
    u32 = int.from_bytes(buf[off:off+4], "little", signed=False)
    f32 = struct.unpack("<f", buf[off:off+4])[0]
    return u32, f32, off + 4

def read_fixed64(buf: bytes, off: int):
    if off + 8 > len(buf):
        raise EOFError("fixed64")
    import struct
    u64 = int.from_bytes(buf[off:off+8], "little", signed=False)
    f64 = struct.unpack("<d", buf[off:off+8])[0]
    return u64, f64, off + 8

def dump_block(b: bytes, width: int = 16, max_bytes: int = 4096) -> str:
    data = b[:min(len(b), max_bytes)]
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off+width]
        hexpart = " ".join(f"{x:02x}" for x in chunk)
        asciip = "".join(chr(x) if 32 <= x <= 126 else "." for x in chunk)
        lines.append(f"{off:04x}: {hexpart:<{width*3-1}}  {asciip}")
    if len(b) > max_bytes:
        lines.append("... (truncated)")
    return "\n".join(lines) if lines else ""

def parse_message(buf: bytes, off: int = 0, length: int = None, nested: bool = True):
    end = len(buf) if length is None else min(len(buf), off + length)
    i = off
    fields = []
    ok = True
    try:
        while i < end:
            start = i
            key, i = read_varint(buf, i)
            field_number = key >> 3
            wire_type = key & 7
            entry = {
                "fieldNumber": field_number,
                "wireType": wire_type,
                "keyOffset": start,
            }
            if wire_type == 0:
                v, i2 = read_varint(buf, i)
                entry["byteRange"] = (start, i2)
                entry["type"] = "varint"
                entry["valueBytes"] = buf[i:i2]
                entry["uint"] = v
                entry["sint"] = zigzag_decode(v)
                i = i2
            elif wire_type == 1:
                u64, f64, i2 = read_fixed64(buf, i)
                entry["byteRange"] = (start, i2)
                entry["type"] = "fixed64"
                entry["u64"] = u64
                entry["double"] = f64
                entry["valueBytes"] = buf[i:i2]
                i = i2
            elif wire_type == 2:
                L, i2 = read_varint(buf, i)
                payload = buf[i2:i2+L]
                entry["byteRange"] = (start, i2 + L)
                entry["type"] = "length_delimited"
                entry["len"] = L
                entry["valueBytes"] = payload
                if is_likely_utf8(payload):
                    entry["string"] = decode_utf8(payload)
                if nested:
                    try:
                        sub = parse_message(payload, 0, len(payload), nested=True)
                        if sub.get("ok") and sub.get("fields"):
                            entry["nested"] = sub
                    except Exception:
                        pass
                i = i2 + L
            elif wire_type == 5:
                u32, f32, i2 = read_fixed32(buf, i)
                entry["byteRange"] = (start, i2)
                entry["type"] = "fixed32"
                entry["u32"] = u32
                entry["float"] = f32
                entry["valueBytes"] = buf[i:i2]
                i = i2
            else:
                ok = False
                break
            fields.append(entry)
    except Exception:
        ok = False
    return {"ok": ok, "start": off, "end": i, "fields": fields}

def parse_frames(buf: bytes, nested: bool = True):
    frames = []
    i = 0
    while i < len(buf):
        m = parse_message(buf, i, len(buf) - i, nested)
        if not m["ok"] or not m["fields"]:
            break
        frames.append(m)
        i = m["end"]
    return {"frames": frames, "consumed": i}

PRIMER_TEXT = """
Protobuf – Kurzleitfaden

Was ist Protobuf?
Google Protocol Buffers ist ein binäres, kompaktes Serialisierungsformat. Es benötigt zur Kompilierzeit eine Schema-Datei (.proto). Die übertragene Wire-Format-Nutzlast enthält jedoch nur Feldnummern + Typen, keine Feldnamen.

Feldschlüssel (Key)
Jedes Feld beginnt mit einem Varint-Key:
key = (field_number << 3) | wire_type
Wire Types:
- 0 VARINT (z. B. int32, int64, bool, enum, sint32/sint64 via ZigZag)
- 1 FIXED64 (64-Bit, z. B. double, fixed64, sfixed64)
- 2 LENGTH_DELIMITED (Prefix-Varint + Payload; z. B. string, bytes, embedded message, packed repeated)
- 5 FIXED32 (32-Bit, z. B. float, fixed32, sfixed32)

Varint & ZigZag
- Varint kodiert ganzzahlige Werte in 7-Bit-Chunks (LSB-first), MSB=1 zeigt an, dass weitere Bytes folgen.
- ZigZag wandelt vorzeichenbehaftete Ganzzahlen in nicht-negative Varints um:
  encode(x) = (x << 1) ^ (x >> 31) (bzw. 63), decode(n) = (n >> 1) ^ -(n & 1).

Length-Delimited
- Aufbau: [len(varint)] [len Bytes Payload]
- Kann UTF‑8 string, rohe bytes, oder eine eingebettete Message enthalten (diese wiederum gleichermaßen aufgebaut).

Unbekannte Felder
- Decoder ohne Schema können die Payload als Bytes anzeigen; mit Heuristik (UTF‑8, verschachtelte Messages) ist dennoch viel interpretierbar.

Konkatenierte Frames
- Mehrere Messages können direkt hintereinander stehen. Der Parser liest dann Message für Message bis zum Ende.

Sicherheit
- Länge prüfen (len), defensive Parses, Maximalgrößen setzen (DoS vermeiden).
"""

class ProtoViewer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Protobuf Viewer – Python GUI (Improved)")
        self.resize(1400, 820)

        m_file = self.menuBar().addMenu("&File")
        act_open = QAction("Open File…", self); act_open.triggered.connect(self.open_file)
        m_file.addAction(act_open)

        m_help = self.menuBar().addMenu("&Help")
        act_primer = QAction("Protobuf Primer…", self); act_primer.triggered.connect(self.show_primer)
        m_help.addAction(act_primer)

        self.btn_open = QPushButton("Open File…"); self.btn_open.clicked.connect(self.open_file)
        self.btn_decode = QPushButton("Decode"); self.btn_decode.clicked.connect(self.decode)
        self.btn_clear = QPushButton("Clear"); self.btn_clear.clicked.connect(self.clear)
        self.chk_nested = QCheckBox("Try nested messages"); self.chk_nested.setChecked(True)
        self.chk_concat = QCheckBox("Parse concatenated frames"); self.chk_concat.setChecked(False)

        self.hex_edit = QTextEdit(); self.hex_edit.setPlaceholderText("Paste hex here (spaces/newlines allowed)…")
        self.quick = QTextEdit(); self.quick.setReadOnly(True); self.quick.setLineWrapMode(QTextEdit.NoWrap)
        self.quick.setPlaceholderText("Quick hex view")

        top_box = QWidget(); top_layout = QHBoxLayout(top_box)
        top_layout.addWidget(self.btn_open); top_layout.addWidget(self.btn_decode); top_layout.addWidget(self.btn_clear)
        top_layout.addStretch(1)
        top_layout.addWidget(self.chk_nested); top_layout.addWidget(self.chk_concat)

        left = QWidget(); left_layout = QVBoxLayout(left)
        left_layout.addWidget(QLabel("Input (Hex)"))
        left_layout.addWidget(self.hex_edit, 2)
        left_layout.addWidget(QLabel("Quick Hex View"))
        left_layout.addWidget(self.quick, 1)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Byte Range", "Field Number", "Type", "Content"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setWordWrap(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self.update_detail_from_selection)

        self.detail = QTextEdit(); self.detail.setReadOnly(True); self.detail.setLineWrapMode(QTextEdit.NoWrap)
        self.detail.setPlaceholderText("Hex dump of selected field")

        right_split = QSplitter(Qt.Vertical)
        right_split.addWidget(self.table)
        right_split.addWidget(self.detail)
        right_split.setStretchFactor(0, 3)
        right_split.setStretchFactor(1, 2)

        main_split = QSplitter(Qt.Horizontal)
        main_split.addWidget(left)
        main_split.addWidget(right_split)
        main_split.setStretchFactor(0, 1)
        main_split.setStretchFactor(1, 2)

        central = QWidget(); central_layout = QVBoxLayout(central)
        central_layout.addWidget(top_box)
        central_layout.addWidget(main_split, 1)
        self.setCentralWidget(central)

        self.current_bytes: bytes = b""
        self.current_frames: List[Dict[str, Any]] = []
        self.row_to_bytes: Dict[int, bytes] = {}

        self.table.setColumnWidth(0, 100)
        self.table.setColumnWidth(1, 100)
        self.table.setColumnWidth(2, 120)
        self.table.setColumnWidth(3, 800)

    def show_primer(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Protobuf Primer")
        layout = QVBoxLayout(dlg)
        txt = QTextEdit(); txt.setReadOnly(True)
        txt.setPlainText(PRIMER_TEXT)
        layout.addWidget(txt)
        bb = QDialogButtonBox(QDialogButtonBox.Ok); bb.accepted.connect(dlg.accept)
        layout.addWidget(bb)
        dlg.resize(720, 560)
        dlg.exec()

    def open_file(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Open Binary File", "", "All Files (*)")
        if not fn: return
        data = Path(fn).read_bytes()
        self.hex_edit.setText(bytes_to_hex(data))
        self.quick.setText(dump_block(data, 16, 512))

    def clear(self):
        self.hex_edit.clear()
        self.quick.clear()
        self.table.setRowCount(0)
        self.detail.clear()
        self.current_bytes = b""
        self.current_frames = []
        self.row_to_bytes.clear()

    def decode(self):
        try:
            b = hex_to_bytes(self.hex_edit.toPlainText())
            self.current_bytes = b
            self.quick.setText(dump_block(b, 16, 512) if b else "No data")
            if not b: return
            if self.chk_concat.isChecked():
                out = parse_frames(b, self.chk_nested.isChecked())
                frames = out["frames"]
            else:
                frames = [parse_message(b, 0, len(b), self.chk_nested.isChecked())]
            self.current_frames = frames
            self.populate_table(frames)
        except Exception as e:
            QMessageBox.critical(self, "Decode error", str(e))

    def populate_table(self, frames: List[Dict[str, Any]]):
        self.table.setRowCount(0)
        self.row_to_bytes.clear()
        row = 0
        wname = {0:"varint", 1:"fixed64", 2:"length_delimited", 5:"fixed32"}
        
        for frame in frames:
            row = self.add_fields_to_table(frame.get("fields", []), row, indent_level=0)

        self.table.resizeRowsToContents()

    def add_fields_to_table(self, fields: List[Dict[str, Any]], start_row: int, indent_level: int = 0) -> int:
        row = start_row
        wname = {0:"varint", 1:"fixed64", 2:"length_delimited", 5:"fixed32"}
        
        for f in fields:
            self.table.insertRow(row)
            
            wt = f.get("wireType")
            wt_name = wname.get(wt, f"WT_{wt}")
            br = f.get("byteRange")
            br_txt = f"{br[0]}-{br[1]}" if br else "—"
            payload: bytes = f.get("valueBytes") or b""
            
            content = self.build_content_text(f, payload, include_nested=False)
            
            indent_prefix = "    " * indent_level
            
            item_br = QTableWidgetItem(br_txt)
            item_fn = QTableWidgetItem(indent_prefix + str(f.get("fieldNumber", "")))
            item_type = QTableWidgetItem(wt_name)
            item_content = QTableWidgetItem(content)
            
            if indent_level > 0:
                bg_colors = [
                    QColor(240, 248, 255),
                    QColor(245, 245, 245),
                    QColor(250, 250, 250),
                ]
                bg_color = bg_colors[min(indent_level - 1, len(bg_colors) - 1)]
                
                for item in [item_br, item_fn, item_type, item_content]:
                    item.setBackground(bg_color)
                
                font = QFont()
                font.setBold(True)
                item_fn.setFont(font)
            
            for item in [item_br, item_fn, item_type, item_content]:
                item.setFlags(item.flags() ^ Qt.ItemIsEditable)
            
            self.table.setItem(row, 0, item_br)
            self.table.setItem(row, 1, item_fn)
            self.table.setItem(row, 2, item_type)
            self.table.setItem(row, 3, item_content)
            
            self.row_to_bytes[row] = payload
            row += 1
            
            if f.get("nested"):
                nested_fields = f["nested"].get("fields", [])
                if nested_fields:
                    row = self.add_fields_to_table(nested_fields, row, indent_level + 1)
        
        return row

    def build_content_text(self, f: Dict[str, Any], payload: bytes, include_nested: bool = True) -> str:
        t = f.get("type")
        if t == "varint":
            return f"As uint: {f.get('uint')} | As sint: {f.get('sint')}"
        if t == "fixed64":
            return f"As uint64: {f.get('u64')} | As double: {f.get('double')}"
        if t == "fixed32":
            return f"As uint32: {f.get('u32')} | As float: {f.get('float')}"

        if t == "length_delimited":
            parts = []
            
            if isinstance(f.get("string"), str):
                s = f.get('string', '')
                parts.append(f"STRING: {s}")
            
            if f.get("nested"):
                nested = f["nested"]
                num_fields = len(nested.get("fields", []))
                parts.append(f"Nested message: {num_fields} field(s)")
            
            if not parts:
                hex_str = bytes_to_hex(payload)
                parts.append(f"BYTES ({len(payload)}): {hex_str}")
            
            return " | ".join(parts)

        return t or ""

    def update_detail_from_selection(self):
        sel = self.table.selectedItems()
        if not sel: return
        row = sel[0].row()
        data = self.row_to_bytes.get(row, b"")
        self.detail.setText(dump_block(data, 16, 4096))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = ProtoViewer()
    w.show()
    sys.exit(app.exec())