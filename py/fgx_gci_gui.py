#!/usr/bin/python

# Graphical interface for F-Zero GX GCI analysis and manipulation functions.
#
# Run this to start the GUI:
# python fgx_gci_gui.py
#
# Requirements:
# Python 3.6+
# pip install PyQt5

from collections import OrderedDict
import csv
import functools
import json
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
from fgx_encode import decoder, encoder
from fgx_format import gci
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
        scroll_area.setFixedSize(500, 400)

        vbox = QVBoxLayout()
        vbox.addWidget(scroll_area)
        self.setLayout(vbox)

    def read_values_from_gci(self, input_data):

        # Be able to look up fields by key
        self.field_lookup = dict()
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
            for field in csv.DictReader(f):
                self.field_lookup[field['key']] = field

                if field.get('parent'):
                    parent_field = self.field_lookup[field['parent']]
                    # Replace field['parent'] so it's an actual field instead
                    # of a key, for later reference
                    field['parent'] = parent_field
                    # Add parent -> child links as well
                    if parent_field.get('children'):
                        parent_field['children'].append(field)
                    else:
                        parent_field['children'] = [field]
                else:
                    self.fields.append(field)

        # We'll grab input bits from this generator as we iterate over fields.
        self.gci_bit_generator = self.generate_gci_bits(input_data)
        # This is handy when evaluating expressions that use field values.
        self.leaf_fields_with_values = set()

        # Read values from the GCI (starting at 0x20A0).
        # Due to arrays, the structure we need for self.values is more complex
        # than self.fields. Example:
        # self.values = dict(
        #     course_id=6, racer_array_element_count=30,
        #     racer_array=[
        #         dict(is_human=1, machine_id=25),
        #         dict(is_human=0, machine_id=7),
        #         ...
        #     ], ...
        # )
        # It's an ordered dict to make outputting values to GCI easier.
        self.values = OrderedDict()
        for field in self.fields:
            self.read_field_value_from_gci(field, self.values)

        self.main_gui.after_process_input_gci.emit()

    def read_field_value_from_gci(self, field, values_dict):
        """
        Fields are encoded in the GCI bit by bit, not byte by byte. For
        example, one field might be 7 bits, the next field might be 5, and so
        on.

        Within a GCI byte, the bits are read from right to left.
        To get the actual field values, we set the bits from left to right.
        So the bits get reversed.
        """
        if field.get('bits'):
            if not field['bits'].isnumeric():
                raise ValueError(
                    f"Field '{field['key']}' doesn't have an integer number of"
                    f" bits: {field['bits']}")
            number_of_bits = int(field['bits'])
            if number_of_bits < 1:
                raise ValueError(
                    f"Field '{field['key']}' has {number_of_bits} bits."
                    " The number should be positive.")
            if number_of_bits > 32:
                raise ValueError(
                    f"Field '{field['key']}' has {number_of_bits} bits."
                    " The number should be 32 or less. Note that this should"
                    " be the number of bits in a single read. A single field"
                    " might do multiple reads.")

        if field['data_type'] == 'hex':

            if not self.is_field_in_use(field):
                values_dict[field['key']] = None
                return

            if field.get('reads'):
                number_of_reads = int(field['reads'])
            else:
                number_of_reads = 1
            bit_generator = self.generate_gci_bits_by_set(
                number_of_bits, number_of_reads)
            bits = []
            byte_array = []
            for bit in bit_generator:
                bits.append(bit)
                if len(bits) == 8:
                    byte_array.append(self.eight_bits_to_byte(bits))
                    bits = []
            # Add remaining bits, if any
            if bits:
                # Pad with 0s on right to get 8 bits total
                bits += [0]*(8 - len(bits))
                byte_array.append(self.eight_bits_to_byte(bits))
            values_dict[field['key']] = byte_array

            self.leaf_fields_with_values.add(field['key'])

        elif field['data_type'] == 'int':

            if not self.is_field_in_use(field):
                values_dict[field['key']] = None
                return

            bits = self.read_bits_from_input(number_of_bits)
            byte_binary_str = ''.join([str(bit) for bit in bits])
            values_dict[field['key']] = int(byte_binary_str, base=2)

            self.leaf_fields_with_values.add(field['key'])

        elif field['data_type'] == 'array':

            array_length = self.evaluate_using_field_values(field['length'])
            if type(array_length) != int:
                raise ValueError(
                    "Array length didn't evaluate as an int:"
                    f" {field['length']}")

            values_dict[field['key']] = []
            for i in range(array_length):
                element_values = OrderedDict()
                # Append the dict to the values structure first...
                values_dict[field['key']].append(element_values)
                # ...then start filling in the dict. This is necessary because
                # later children might depend on the values of earlier
                # children.
                for child_field in field['children']:
                    self.read_field_value_from_gci(
                        child_field, element_values)

        else:

            raise ValueError(
                f"Field '{field['key']}' has an unsupported data_type:"
                f" {field['data_type']}")

    def is_field_in_use(self, field):
        if field.get('condition'):
            condition_value = self.evaluate_using_field_values(
                field['condition'])
            if type(condition_value) != bool:
                raise ValueError(
                    "Field condition didn't evaluate as a bool:"
                    f" {field['condition']}")
            return condition_value
        return True

    def evaluate_using_field_values(self, expression_str):
        # We'll eval() the expression using the field values as the
        # global namespace: <field key> = <field value>
        eval_globals = dict([
            (key, self.get_field_value(self.field_lookup[key]))
            for key in self.leaf_fields_with_values
        ])
        return eval(expression_str, eval_globals)

    @staticmethod
    def eight_bits_to_byte(bit_list):
        byte_binary_str = ''.join([str(bit) for bit in bit_list])
        return int(byte_binary_str, base=2)

    def generate_gci_bits_by_set(self, bits_per_set, number_of_sets):
        for i in range(number_of_sets):
            bit_set = self.read_bits_from_input(bits_per_set)
            for bit in bit_set:
                yield bit

    def read_bits_from_input(self, number_of_bits):
        return [next(self.gci_bit_generator) for i in range(number_of_bits)]

    @staticmethod
    def generate_gci_bits(input_data):
        """
        Generator function to get the input GCI's bits. Reads bytes in order,
        reads bits in reverse order (least to most significant).
        """
        for byte in input_data:
            for i in range(8):
                yield (byte >> i) & 1

    def output_values_to_gci(self):
        output_bits = []

        # Since self.values is an OrderedDict, this should work for getting
        # values in order.
        for field_key, field_value in self.values.items():
            field = self.field_lookup[field_key]
            output_bits.extend(
                self.output_field_value_for_gci(field, field_value))

        bits = []
        byte_array = []
        for bit in output_bits:
            bits.append(bit)
            if len(bits) == 8:
                bits.reverse()
                byte_array.append(self.eight_bits_to_byte(bits))
                bits = []
        # Add remaining bits, if any
        if bits:
            bits.reverse()
            # Pad with 0s on left to get 8 bits total
            bits = (['0']*(8 - len(bits))) + bits
            byte_array.append(self.eight_bits_to_byte(bits))

        return byte_array

    def output_field_value_for_gci(self, field, value):
        """Return a list of bit strings ('0' or '1')."""
        if value is None:
            return []

        if field['data_type'] == 'hex':

            output_bits = []
            bits_remaining = int(field['bits']) * int(field.get('reads') or 1)
            # value is a byte array
            for byte_value in value:
                bits_this_time = min(bits_remaining, 8)
                byte_as_binary_str = format(byte_value, f'0{bits_this_time}b')
                output_bits.extend(byte_as_binary_str)
            return output_bits

        elif field['data_type'] == 'int':

            number_of_bits = field['bits']
            return format(value, f'0{number_of_bits}b')

        elif field['data_type'] == 'array':

            output_bits = []
            for element_dict in value:
                # We assume this is an OrderedDict.
                for child_key, child_value in element_dict.items():
                    child_field = self.field_lookup[child_key]
                    output_bits.extend(
                        self.output_field_value_for_gci(
                            child_field, child_value))
            return output_bits

    def add_field_widgets(self):
        # Clear field widgets added from the previous input GCI. We do
        # this because each widget set is specific to a particular GCI type
        # (replay, ghost, etc.)
        clear_qlayout(self.fields_vbox)

        for field in self.fields:
            self.add_field_widget(field, self.fields_vbox)

    def add_field_widget(self, field, container):
        label = QLabel(field['label'])
        label.setWordWrap(True)
        label.setFixedWidth(100)

        field_hbox = QHBoxLayout()
        field_hbox.addWidget(label)

        if field['data_type'] == 'int':

            line_edit = QLineEdit()
            callback = functools.partial(self.on_field_edit, field['key'])
            line_edit.editingFinished.connect(callback)
            field['edit_widget'] = line_edit
            field_hbox.addWidget(line_edit)

            container.addLayout(field_hbox)
            self.field_value_to_widget_text(field)

        elif field['data_type'] == 'hex':

            text_edit = QTextEdit()
            bit_count = int(field['bits']) * int(field.get('reads') or 1)
            line_count = math.ceil(bit_count / (8*16))
            text_edit.setFixedHeight(min(line_count * 26, 250))
            field['edit_widget'] = text_edit
            field_hbox.addWidget(text_edit)

            # Was thinking of adding this callback to respond to user edits,
            # but this signal responds to clear() and append() as well,
            # and there doesn't seem to be a better signal to use.
            # Just not bothering with hex editing for now.
            #callback = functools.partial(self.on_field_edit, field['key'])
            #text_edit.textChanged.connect(callback)
            text_edit.setReadOnly(True)

            container.addLayout(field_hbox)
            self.field_value_to_widget_text(field)

        elif field['data_type'] == 'array':

            # Dropdown to change the array index. This controls what values
            # are shown in the array-element-struct fields.
            array_index_combo_box = QComboBox()
            array_length = len(self.get_field_value(field))
            array_index_combo_box.addItems(
                [str(i) for i in range(array_length)])
            array_index_combo_box.setCurrentText('0')
            callback = functools.partial(
                self.on_array_field_index_change, field['key'])
            array_index_combo_box.activated[str].connect(callback)
            field['array_index_combo_box'] = array_index_combo_box
            field_hbox.addWidget(array_index_combo_box)

            # Recurse on sub-fields
            sub_field_vbox = QVBoxLayout()
            for child_field in field['children']:
                self.add_field_widget(child_field, sub_field_vbox)

            # Make left margin a little bigger than default
            sub_field_vbox.setContentsMargins(15, 0, 0, 0)
            container.addLayout(field_hbox)
            container.addLayout(sub_field_vbox)

        else:

            raise ValueError(f"Unsupported data_type: {field['data_type']}")

    def field_value_to_widget_text(self, field):
        """Fill the field's widget text with the field's current value."""

        if field['data_type'] == 'int':

            value = self.get_field_value(field)
            if value is not None:
                field['edit_widget'].setText(str(value))
            else:
                field['edit_widget'].setText("")

        elif field['data_type'] == 'hex':

            # We start with an array of byte-integers,
            # and create something like: 'A0 87 F3 C4  29 7B FF 6E\n13 DA'

            field['edit_widget'].clear()

            byte_values = self.get_field_value(field)
            if byte_values is None:
                return

            # Write 16 bytes per line
            current_line_bytes = []
            for b in byte_values:
                current_line_bytes.append(b)
                if len(current_line_bytes) == 16:
                    field['edit_widget'].append(
                        self.sixteen_bytes_to_hex_str(current_line_bytes))
                    current_line_bytes = []
            # Write the last partial line, if any
            if current_line_bytes:
                field['edit_widget'].append(
                    self.sixteen_bytes_to_hex_str(current_line_bytes))

        elif field['data_type'] == 'array':

            # Here we want to update all the widgets within this array.
            for child_field in field['children']:
                # Recurse
                self.field_value_to_widget_text(child_field)

    def field_widget_text_to_value(self, field):
        """Update the field's current value according to the field's widget
        text."""

        if field['data_type'] == 'int':

            text = field['edit_widget'].text()
            try:
                self.set_field_value(field, int(text))
            except ValueError:
                # Typed value is invalid. Revert to the original value.
                self.field_value_to_widget_text(field)

        elif field['data_type'] == 'hex':

            # We expect something like: 'A0 87 F3 C4  29 7B FF 6E\n13 DA'
            # And want to turn that into an array of byte-integers.
            text = field['edit_widget'].toPlainText()

            # Get whitespace-separated tokens. Each token is taken to be a
            # byte value in hex.
            byte_hex_strs = text.split()
            byte_values = []
            for s in byte_hex_strs:
                try:
                    byte_value = int(s, base=16)
                    if byte_value < 0 or byte_value > 255:
                        raise ValueError
                    byte_values.append(byte_value)
                except ValueError:
                    # Typed value is invalid; the byte values include non-ints
                    # or values not between 0 and 255.
                    # Revert to the original value.
                    self.field_value_to_widget_text(field)
                    return
            # All bytes are valid
            self.set_field_value(field, byte_values)

    def get_current_array_index(self, field):
        if field.get('array_index_combo_box'):
            return int(field['array_index_combo_box'].currentText())
        else:
            # We must be in the middle of initializing. We should be
            # currently initializing the latest added array element,
            # so we want to use values from that element.
            element_count_so_far = len(self.get_field_value(field))
            return element_count_so_far - 1

    def get_field_value(self, field):
        """
        Gets the value of the given field, according to the currently
        selected array indices. Returns None if not available.
        """
        if field.get('parent'):
            parent = field['parent']
            if parent['data_type'] == 'array':
                array_index = self.get_current_array_index(parent)
                # Recurse up the hierarchy
                parent_value = self.get_field_value(parent)
                return parent_value[array_index].get(field['key'])
            else:
                raise ValueError(
                    "The only kind of parent-child relationship supported is"
                    " where the parent is an array. Here the parent is a(n)"
                    " {parent['data_type']}.")
        else:
            return self.values.get(field['key'])

    def set_field_value(self, field, new_value):
        if field.get('parent'):
            parent = field['parent']
            if parent['data_type'] == 'array':
                array_index = int(
                    parent['array_index_combo_box'].currentText())
                # Recurse up the hierarchy
                parent_value = self.get_field_value(parent)
                parent_value[array_index][field['key']] = new_value
            else:
                raise ValueError(
                    "The only kind of parent-child relationship supported is"
                    " where the parent is an array. Here the parent is a(n)"
                    " {parent['data_type']}.")
        else:
            self.values[field['key']] = new_value

    def on_field_edit(self, field_key):
        field = self.field_lookup[field_key]
        self.field_widget_text_to_value(field)

    def on_array_field_index_change(self, field_key):
        field = self.field_lookup[field_key]
        self.field_value_to_widget_text(field)

    @staticmethod
    def sixteen_bytes_to_hex_str(byte_values):
        """
        Takes an iterable of up to 16 bytes, and returns a string like:
        47 46 5A 45 38 50 FF 02   66 7A 72 30 30 30 30 41
        """
        bytes_0_to_7 = ' '.join([format(b, '02X') for b in byte_values[:8]])
        if len(byte_values) > 8:
            bytes_8_to_f = ' '.join(
                [format(b, '02X') for b in byte_values[8:]])
            return f"{bytes_0_to_7}   {bytes_8_to_f}"
        else:
            return bytes_0_to_7


# This is true when calling from command line.
if __name__ == '__main__':

    app = QApplication(sys.argv)
    widget = MainWidget()
    sys.exit(app.exec_())
