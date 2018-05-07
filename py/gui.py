#!/usr/bin/python

# Graphical interface for F-Zero GX GCI analysis and manipulation functions.
#
# Run this to start the GUI:
# python fgx_gci_gui.py
#
# Requirements:
# Python 3.6+
# pip install PyQt5

import csv
import functools
import math
import os
from pathlib import Path
import sys
import urllib.parse
import urllib.request

from PyQt5.QtCore import pyqtSignal, pyqtSlot, Qt, QThread
from PyQt5.QtWidgets import (QApplication, QComboBox, QDialog,
    QDialogButtonBox, QFileDialog, QHBoxLayout, QLabel, QLayout, QLineEdit,
    QPushButton, QScrollArea, QTextEdit, QVBoxLayout, QWidget, QWidgetItem)

from config import config
from exceptions import FieldSpecError
from fgx_encode import decoder, encoder
from fgx_format import gci
from fields import (
    ArrayField, DictField, Field, FloatField, HexField, IntField, LongHexField,
    ValueField)
from widgets_qt import (
    QComboBoxWidget, QLineEditWidget, QTextEditReadOnlyWidget, QTextEditWidget)
from worker import WorkerThread


def clear_qlayout(layout):
    """
    Removes all elements from a QLayout.
    General idea from https://stackoverflow.com/a/25330164/
    Except this also goes recursively through QLayouts within
    QLayouts.
    """
    while not layout.isEmpty():
        layout_item = layout.takeAt(0)
        if isinstance(layout_item, QLayout):
            clear_qlayout(layout_item)
            child = layout_item
        elif isinstance(layout_item, QWidgetItem):
            child = layout_item.widget()
        layout.removeItem(layout_item)
        child.setParent(None)


class MainWidget(QWidget):

    after_process_input_gci = pyqtSignal()

    def __init__(self):
        super().__init__()

        self.init_layout()
        self.output_filename_defaults = dict(
            gci='',
            replay_array='',
        )

        self.worker_thread = None
        self.after_process_input_gci.connect(self._after_process_input_gci)

        # Accept drag and drop; see event methods for details
        self.setAcceptDrops(True)

    def init_layout(self):

        self.error_label = QLabel("")
        self.error_label.setStyleSheet("QLabel { color: red; }")

        self.input_gci_label = QLabel("Drag and drop a .gci to get started")
        # Given that we have word wrap True, setting a fixed height prevents
        # the GUI from resizing (and prevents an associated window size warning
        # in the console window) when we switch between long and short
        # filepaths.
        # To help with reading long filepaths, we'll also set a tooltip each
        # time we set the filepath.
        self.input_gci_label.setWordWrap(True)
        self.input_gci_label.setMinimumWidth(150)
        self.input_gci_label.setFixedHeight(35)

        self.input_gci_checksum_label = QLabel("")

        self.gci_fields_widget = GCIFieldsWidget(self)

        self.output_button = QPushButton("Output", self)
        self.output_button.clicked.connect(self.on_output_button_click)

        self.output_type_combo_box = QComboBox(self)
        # The choices here only apply to replays. If we handle other types of
        # .gci's in the future, we might change this combo box to add its
        # choices dynamically.
        self.output_type_combo_box.addItems(
            [".gci", "Replay array .bin"])
        self.output_type_combo_box.activated[str].connect(
            self.on_output_type_change)

        self.output_folder_select_dialog = QFileDialog(
            self, "Choose folder to save to", self.output_folder)
        self.output_folder_label = QLabel(self.output_folder)
        self.output_folder_label.setToolTip(self.output_folder)
        self.output_folder_label.setWordWrap(True)
        self.output_folder_label.setMinimumWidth(150)
        self.output_folder_label.setFixedHeight(50)
        self.output_folder_select_button = QPushButton("Choose", self)
        self.output_folder_select_button.clicked.connect(
            self.show_output_folder_select_dialog)

        self.output_filename_line_edit = QLineEdit()
        self.output_filename_line_edit.editingFinished.connect(
            self.on_output_filename_change)

        output_type_hbox = QHBoxLayout()
        output_type_hbox.addWidget(self.output_button)
        output_type_hbox.addWidget(self.output_type_combo_box)
        output_folder_hbox = QHBoxLayout()
        output_folder_hbox.addWidget(QLabel("to folder:"))
        output_folder_hbox.addWidget(self.output_folder_label)
        output_folder_hbox.addWidget(self.output_folder_select_button)
        output_filename_hbox = QHBoxLayout()
        output_filename_hbox.addWidget(QLabel("with filename:"))
        output_filename_hbox.addWidget(self.output_filename_line_edit)
        self.output_vbox = QVBoxLayout()
        self.output_vbox.addLayout(output_type_hbox)
        self.output_vbox.addLayout(output_folder_hbox)
        self.output_vbox.addLayout(output_filename_hbox)
        self.output_vbox_widget = QWidget()
        self.output_vbox_widget.setLayout(self.output_vbox)
        self.output_vbox_widget.hide()

        vbox = QVBoxLayout()
        vbox.addWidget(self.error_label)
        vbox.addWidget(self.input_gci_label)
        vbox.addWidget(self.input_gci_checksum_label)
        vbox.addWidget(self.gci_fields_widget)
        vbox.addWidget(self.output_vbox_widget)
        self.setLayout(vbox)

        self.setWindowTitle("F-Zero GX GCI info")
        self.show()

    def clear_error_display(self):
        self.error_label.setText("")

    def display_error(self, message):
        self.error_label.setText(message)

    def show_output_folder_select_dialog(self):
        folder = self.output_folder_select_dialog.getExistingDirectory(
            self, 'Choose folder')
        if folder:
            self.output_folder_label.setText(folder)
            self.output_folder_label.setToolTip(folder)
            config.set('output_folder', folder)

    def run_worker_job(self, job_func):
        if not self.worker_thread:
            # Create a thread.
            # Must store a reference to the thread in a non-local variable,
            # so the thread doesn't get garbage collected after returning
            # from this method
            # https://stackoverflow.com/a/15702922/
            self.worker_thread = WorkerThread()

        # This will emit 'started' and start running the thread
        self.worker_thread.run_job(job_func)

    def closeEvent(self, e):
        """Event handler: GUI window is closed"""
        config.save()

    def dragEnterEvent(self, e):
        """Event handler: Mouse enters the GUI window while dragging
        something"""
        e.accept()

    def dropEvent(self, e):
        """
        Event handler: Mouse is released on the GUI window after dragging.

        Check that we've dragged a single .gci file. If so, process it.
        """
        self.clear_error_display()

        mime_data = e.mimeData()
        dropped_uris = [uri.toString() for uri in mime_data.urls()]
        if len(dropped_uris) > 1:
            self.display_error("Please drag and drop a single file.")
            return

        uri = urllib.parse.urlparse(dropped_uris[0])
        uri_scheme = uri.scheme
        if uri_scheme != 'file':
            self.display_error(
                "Please drag and drop a file from your computer.")
            return

        # url2pathname() will:
        # - Replace URL-like escape codes such as %E3%83%BB
        #   with unescaped Unicode characters.
        # - Strip the beginning slash if it's a Windows filepath.
        #   (/D:/Games/... -> D:\Games\...)
        input_gci_filepath = Path(urllib.request.url2pathname(uri.path))
        if input_gci_filepath.suffix != '.gci':
            self.display_error(
                "The dropped file doesn't seem to be a .gci.")
            return

        self.input_gci_filepath = input_gci_filepath
        self.process_input_gci()

    def process_input_gci(self):
        self.input_gci_label.setText("Working...")
        self.input_gci = gci(self.input_gci_filepath)
        input_data = self.input_gci.get_replay_data()

        Field.reset_field_structures()

        success = self.gci_fields_widget.read_fields_from_spec()
        if not success:
            self.input_gci_label.setText("Drag and drop a .gci to get started")
            return

        # Process the replay-specific GCI contents.
        # This call can take a while, especially with custom machines.
        self.run_worker_job(
            functools.partial(
                self.gci_fields_widget.read_values_from_gci, input_data))

    @pyqtSlot()
    def _after_process_input_gci(self):
        self.gci_fields_widget.add_field_widgets()

        self.input_gci_label.setText(f"Input: {self.input_gci_filepath}")
        self.input_gci_label.setToolTip(f"Input: {self.input_gci_filepath}")
        self.input_gci_checksum_label.setText(
            f"\nChecksum: 0x{self.input_gci.get_checksum().hex()}")

        self.output_filename_defaults = dict(
            gci='output.gci',
            replay_array=f'{self.input_gci_filepath.stem}__replay_array.bin',
        )
        self.output_vbox_widget.show()
        self.on_output_type_change()

    @property
    def output_type(self):
        combo_box_text = self.output_type_combo_box.currentText()
        if combo_box_text == ".gci":
            return 'gci'
        elif combo_box_text == "Replay array .bin":
            return 'replay_array'

    @property
    def output_folder(self):
        return config.get('output_folder', '')

    @property
    def output_filename(self):
        fn = config.get(f'output_filename_{self.output_type}')
        if not fn:
            fn = self.output_filename_defaults[self.output_type]
        return fn

    @property
    def output_filepath(self):
        return Path(self.output_folder, self.output_filename)

    def on_output_type_change(self):
        output_filename = config.get(
            f'output_filename_{self.output_type}', '')
        self.output_filename_line_edit.setText(output_filename)
        self.output_filename_line_edit.setPlaceholderText(
            self.output_filename_defaults[self.output_type])

    def on_output_filename_change(self):
        config.set(
            f'output_filename_{self.output_type}',
            self.output_filename_line_edit.text())

    def on_output_button_click(self):
        self.clear_error_display()

        if not self.output_folder:
            self.display_error("Please select an output folder.")
            return

        if self.output_type == 'gci':
            self.output_gci()
        elif self.output_type == 'replay_array':
            self.output_replay_array()

    def output_gci(self):
        # Re-encode the replay data
        new_replay_data = self.gci_fields_widget.output_values_to_gci()
        # Zero-pad to make the entire GCI a multiple of 0x2000 bytes + 0x40.
        # This replay data does not include the first 0x20A0 bytes of the GCI.
        gci_bytes_without_padding = len(new_replay_data) + 0x20A0
        gci_target_blocks = math.ceil(
            (gci_bytes_without_padding - 0x40) / 0x2000)
        gci_target_bytes = (gci_target_blocks * 0x2000) + 0x40
        zero_padding = [0] * (gci_target_bytes - gci_bytes_without_padding)
        new_replay_data.extend(zero_padding)

        # Concatenate new replay data to the rest of the original GCI
        self.input_gci.set_replay_data(new_replay_data)

        # Recompute the checksum of the whole GCI
        self.input_gci.recompute_checksum()

        # Write the new GCI to a file
        self.output_binary_file(self.input_gci.raw_bytes)

        # Success dialog
        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(
            f"GCI written to: {self.output_filepath}"
            f"\nChecksum: 0x{self.input_gci.get_checksum().hex()}"
        ))
        vbox.addWidget(button_box)
        confirmed_dialog = QDialog(self)
        confirmed_dialog.setWindowTitle("Write success")
        confirmed_dialog.setLayout(vbox)
        # Make the OK button 'accept' the dialog
        button_box.accepted.connect(confirmed_dialog.accept)
        # Show the dialog
        confirmed_dialog.exec()

    def output_replay_array(self):
        self.display_error("Replay-array output mode isn't implemented yet.")

    def output_binary_file(self, bytes_to_write):
        with open(self.output_filepath, "wb") as output_file:
            output_file.write(bytes_to_write)


class GCIFieldsWidget(QWidget):

    def __init__(self, main_gui):
        super().__init__()
        self.main_gui = main_gui
        self.init_layout()

    def init_layout(self):
        self.fields_vbox = QVBoxLayout()

        scrollable_box = QWidget()
        scrollable_box.setLayout(self.fields_vbox)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(scrollable_box)
        scroll_area.setFixedSize(550, 400)

        vbox = QVBoxLayout()
        vbox.addWidget(scroll_area)
        self.setLayout(vbox)

    def read_fields_from_spec(self):
        # Ordered field list. Determines the order we read in fields from
        # the input file, and the order we display widgets to view/edit
        # the field values.
        # Fields can have child fields too, so it's a tree structure.
        # The most common kind of parent-child relationship is when there's an
        # array, and each element in that array is a struct of multiple fields.
        self.fields = []

        # Read field specifications from CSV, one field per row.
        # We'll read in each field as a dict. The first row in the CSV file
        # specifies the dict keys.
        # Here we are automatically assuming a replay file, but maybe we'll
        # detect and support other GCI types like ghosts later.
        with open('replay_fields.csv', 'r') as f:

            for field_spec in csv.DictReader(f):

                try:
                    if field_spec['data_type'] == '':
                        raise FieldSpecError(
                            "One of the fields is missing a data_type.")
                    field_type = field_spec['data_type']

                    if field_type == 'array':
                        field = ArrayField(field_spec, QComboBoxWidget())
                    elif field_type == 'dict':
                        field = DictField(field_spec)
                    elif field_type == 'float':
                        field = FloatField(field_spec, QLineEditWidget())
                    elif field_type == 'hex':
                        field = HexField(field_spec, QLineEditWidget())
                    elif field_type == 'hex_long_read_only':
                        # We don't support editable QTextEdits, because
                        # QTextEdit doesn't have a callback that only responds
                        # to user edits; it responds to any function that edits
                        # the text content. This results in an infinite loop
                        # during the text -> value -> text back-and-forth
                        # writing that we do to ensure consistent text format.
                        field = LongHexField(
                            field_spec, QTextEditReadOnlyWidget())
                    elif field_type == 'int':
                        field = IntField(field_spec, QLineEditWidget())
                    else:
                        raise FieldSpecError(
                            "One of the fields has an unsupported data_type:"
                            f" {field_type}")

                except FieldSpecError as e:
                    self.main_gui.display_error(
                        f"Fields CSV error: {e}")
                    return False

                # Add top-level fields to self.fields
                if not field.parent:
                    self.fields.append(field)

        return True

    def read_values_from_gci(self, input_data):

        # We'll grab input bits from this generator as we iterate over fields.
        self.gci_bit_generator = self.generate_gci_bits(input_data)

        for field in self.fields:
            field.read_value_from_gci(Field.values, self.generate_x_gci_bits)

        self.main_gui.after_process_input_gci.emit()

    def generate_x_gci_bits(self, number_of_bits):
        for i in range(number_of_bits):
            yield next(self.gci_bit_generator)

    @staticmethod
    def generate_gci_bits(byte_array):
        """
        Generator function to get bits from a replay GCI.

        Fields are encoded in the GCI bit by bit, not byte by byte. For
        example, one field might be 7 bits, the next field might be 5, and so
        on.

        Bytes are read in order; bits within a byte are read in reverse order
        (least significant bit to most significant bit).
        """
        for byte in byte_array:
            for i in range(8):
                yield (byte >> i) & 1

    def output_values_to_gci(self):
        output_bits = []

        # Since Field.values is an OrderedDict, this should work for getting
        # values in order.
        for field_key, field_value in Field.values.items():
            field = Field.field_lookup[field_key]
            output_bits.extend(field.value_to_bits(field_value))

        bits = []
        byte_array = []
        for bit in output_bits:
            bits.append(bit)
            if len(bits) == 8:
                bits.reverse()
                byte_array.append(Field.eight_bits_to_byte(bits))
                bits = []
        # Add remaining bits, if any
        if bits:
            bits.reverse()
            # Pad with 0s on left to get 8 bits total
            bits = (['0']*(8 - len(bits))) + bits
            byte_array.append(Field.eight_bits_to_byte(bits))

        return byte_array

    def add_field_widgets(self):
        # Before clearing previous field widgets, remove focus from whatever
        # widget we might be focused on right now. If focus runs between the
        # old elements as they're getting deleted, that can cause problems with
        # focus-based signals like editingFinished.
        focused_widget = QApplication.focusWidget()
        if focused_widget:
            focused_widget.clearFocus()

        # Clear field widgets added from the previous input GCI. We do
        # this because each widget set is specific to a particular GCI type
        # (replay, ghost, etc.)
        clear_qlayout(self.fields_vbox)

        for field in self.fields:
            self.add_field_widget(field, self.fields_vbox)

    def add_field_widget(self, field, container):
        label = QLabel(field.label)
        label.setWordWrap(True)
        label.setFixedWidth(100)

        field_hbox = QHBoxLayout()
        field_hbox.addWidget(label)

        if isinstance(field, ValueField):

            field_hbox.addWidget(field.value_widget.get_qt_widget())
            container.addLayout(field_hbox)
            field.value_to_widget()

        elif isinstance(field, DictField):

            # Add a spacer, so the label sits on the left instead of the center
            field_hbox.addStretch(1)

            children_vbox = QVBoxLayout()
            # Add left margin
            children_vbox.setContentsMargins(15, 0, 0, 0)
            # Recurse on child fields
            for child_field in field.children:
                self.add_field_widget(child_field, children_vbox)

            container.addLayout(field_hbox)
            container.addLayout(children_vbox)

        elif isinstance(field, ArrayField):

            field.update_index_choices()
            field_hbox.addWidget(field.index_widget.get_qt_widget())

            children_vbox = QVBoxLayout()
            # Add left margin
            children_vbox.setContentsMargins(15, 0, 0, 0)
            # Recurse on child fields
            for child_field in field.children:
                self.add_field_widget(child_field, children_vbox)

            container.addLayout(field_hbox)
            container.addLayout(children_vbox)

        else:

            raise ValueError(
                "Don't know how to add a widget for this field type:"
                f" {type(field)}")


# This is true when calling from command line.
if __name__ == '__main__':

    app = QApplication(sys.argv)
    widget = MainWidget()
    sys.exit(app.exec_())
