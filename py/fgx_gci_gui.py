#!/usr/bin/python

# Graphical interface for F-Zero GX GCI analysis and manipulation functions.
#
# Run this to start the GUI:
# python fgx_gci_gui.py
#
# Requirements:
# Python 3.6+
# pip install PyQt5

import functools
import json
import os
from pathlib import Path
import sys
import urllib.parse
import urllib.request

from PyQt5.QtCore import pyqtSignal, pyqtSlot, QFile, QObject, Qt, QThread
from PyQt5.QtGui import QIcon, QTextCursor
from PyQt5.QtWidgets import (QApplication, QComboBox, QDialog,
    QDialogButtonBox, QFileDialog, QHBoxLayout, QLabel, QLayout, QLineEdit,
    QPushButton, QTextEdit, QVBoxLayout, QWidget, QWidgetItem)

from fgx_encode import decoder, encoder
from fgx_format import gci


class MainWidget(QWidget):

    def __init__(self):
        super().__init__()

        self.config_filename = Path('gui_config.json')
        self.load_config()

        self.init_layout()
        self.output_filename_defaults = dict(
            gci='',
            replay_array='',
        )

        # Accept drag and drop; see event methods for details
        self.setAcceptDrops(True)

    def init_layout(self):

        self.error_label = QLabel("")
        self.error_label.setStyleSheet("QLabel { color: red; }")

        self.input_gci_label = QLabel("Drag and drop a .gci to get started")
        self.input_gci_label.setMinimumWidth(150)
        self.input_gci_label.setWordWrap(True)

        self.fields_vbox = QVBoxLayout()

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
        self.output_folder_label.setMinimumWidth(150)
        self.output_folder_label.setWordWrap(True)
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
        vbox.addLayout(self.fields_vbox)
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
            self.config['output_folder'] = folder

    def closeEvent(self, e):
        """Event handler: GUI window is closed"""
        self.save_config()

    def dragEnterEvent(self, e):
        """Event handler: Mouse enters the GUI window while dragging
        something"""
        e.accept()

    def dropEvent(self, e):
        """Event handler: Mouse is released on the GUI window after dragging"""
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
        input_filepath = Path(urllib.request.url2pathname(uri.path))

        self.input_gci_label.setText(f"Input: {input_filepath}")

        self.output_filename_defaults = dict(
            gci='output.gci',
            replay_array=f'{input_filepath.stem}__replay_array.bin',
        )
        self.output_vbox_widget.show()
        self.on_output_type_change()

        self.process_input_gci(input_filepath)

    def sixteen_bytes_to_hex_str(self, bytes_to_write):
        """
        Takes an iterable of up to 16 bytes, and returns a string like:
        47 46 5A 45 38 50 FF 02   66 7A 72 30 30 30 30 41
        """
        bytes_0_to_7 = ' '.join([format(b, '02X') for b in bytes_to_write[:8]])
        if len(bytes_to_write) > 8:
            bytes_8_to_f = ' '.join(
                [format(b, '02X') for b in bytes_to_write[8:]])
            return f"{bytes_0_to_7}   {bytes_8_to_f}"
        else:
            return bytes_0_to_7

    def write_16_bytes_per_line(self, bytes_to_write, text_edit):
        current_line_bytes = []
        for b in bytes_to_write:
            current_line_bytes.append(b)
            if len(current_line_bytes) == 16:
                text_edit.append(
                    self.sixteen_bytes_to_hex_str(current_line_bytes))
                current_line_bytes = []
        # Write the last partial line, if any
        if current_line_bytes:
            text_edit.append(self.sixteen_bytes_to_hex_str(current_line_bytes))

    def get_field_value(self, field):
        if field['access_type'] == 'top_level':
            return getattr(self.replay, field['key'])
        elif field['access_type'] == 'player_array_dict':
            # This only gets the value for element 0.
            # There should be a way to get for any element. The UI would
            # probably involve a dropdown to select which element we want.
            return self.replay.player_array_dict[0][field['key']]

    def set_field_value(self, field, new_value):
        if field['access_type'] == 'top_level':
            setattr(self.replay, field['key'], new_value)
        elif field['access_type'] == 'player_array_dict':
            # This only sets the value for element 0.
            # There should be a way to set for any element.
            self.replay.player_array_dict[0][field['key']] = new_value

    def on_field_edit(self, field_key):
        field = self.field_lookup[field_key]
        text = field['line_edit'].text()
        try:
            # This assumes an integer field. We may add more data types later.
            self.set_field_value(field, int(text))
        except ValueError:
            # Typed value is invalid. Revert to the original value.
            field['line_edit'].setText(str(self.get_field_value(field)))

    def clear_qlayout(self, layout):
        """
        Removes all elements from a QLayout.
        General idea from https://stackoverflow.com/a/25330164/
        Except this also goes recursively through QLayouts within
        QLayouts.
        """
        while not layout.isEmpty():
            layout_item = layout.takeAt(0)
            if isinstance(layout_item, QLayout):
                self.clear_qlayout(layout_item)
                child = layout_item
            elif isinstance(layout_item, QWidgetItem):
                child = layout_item.widget()
            layout.removeItem(layout_item)
            child.setParent(None)

    def process_input_gci(self, input_filepath):
        self.input_gci = gci(input_filepath)
        self.input_gci_label.setText(
            f"{self.input_gci_label.text()}"
            f"\nChecksum: 0x{self.input_gci.get_checksum().hex()}")
        # Decode the replay data
        my_decoder = decoder(self.input_gci.get_replay_data())
        # Get the decoded data
        self.replay = my_decoder.dump()

        self.fields = [
            dict(
                key='course_id', name="Course ID",
                access_type='top_level'),
            dict(
                key='player_array_entries', name="Player Array entries",
                access_type='top_level'),
            dict(
                key='total_frames', name="Total frames",
                access_type='top_level'),
            dict(
                key='char_id', name="Machine ID",
                access_type='player_array_dict'),
            dict(
                key='member_0x2', name="0x2",
                access_type='player_array_dict'),
            dict(
                key='accel_speed_slider', name="Accel/maxspeed slider",
                access_type='player_array_dict'),
            dict(
                key='member_0x4', name="0x4",
                access_type='player_array_dict'),
            dict(
                key='is_custom_ship', name="Custom boolean",
                access_type='player_array_dict'),
        ]

        self.field_lookup = dict([(d['key'], d) for d in self.fields])
        # Clear elements from previous input GCIs
        self.clear_qlayout(self.fields_vbox)

        for field in self.fields:
            label = QLabel(field['name'])
            label.setMinimumWidth(150)

            line_edit = QLineEdit()
            line_edit.setText(str(self.get_field_value(field)))
            callback = functools.partial(self.on_field_edit, field['key'])
            line_edit.editingFinished.connect(callback)
            field['line_edit'] = line_edit

            field_hbox = QHBoxLayout()
            field_hbox.addWidget(label)
            field_hbox.addWidget(line_edit)
            self.fields_vbox.addLayout(field_hbox)

    @property
    def output_type(self):
        combo_box_text = self.output_type_combo_box.currentText()
        if combo_box_text == ".gci":
            return 'gci'
        elif combo_box_text == "Replay array .bin":
            return 'replay_array'

    @property
    def output_folder(self):
        return self.config.get('output_folder', '')

    @property
    def output_filename(self):
        fn = self.config.get(f'output_filename_{self.output_type}')
        if not fn:
            fn = self.output_filename_defaults[self.output_type]
        return fn

    @property
    def output_filepath(self):
        return Path(self.output_folder, self.output_filename)

    def on_output_type_change(self):
        output_filename = self.config.get(
            f'output_filename_{self.output_type}', '')
        self.output_filename_line_edit.setText(output_filename)
        self.output_filename_line_edit.setPlaceholderText(
            self.output_filename_defaults[self.output_type])

    def on_output_filename_change(self):
        self.config[f'output_filename_{self.output_type}'] = \
            self.output_filename_line_edit.text()

    def on_output_button_click(self):
        if not self.output_folder:
            self.display_error("Please select an output folder.")
            return

        if self.output_type == 'gci':
            self.output_gci()
        elif self.output_type == 'replay_array':
            self.output_replay_array()

    def output_gci(self):
        # Re-encode the replay data
        my_encoder = encoder()
        new_replay_data = my_encoder.encode_gci(self.replay)

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

    def load_config(self):
        if self.config_filename.exists():
            with open(self.config_filename, 'r') as config_file:
                self.config = json.load(config_file)
        else:
            self.config = dict()

    def save_config(self):
        with open(self.config_filename, 'w') as config_file:
            json.dump(self.config, config_file)


# This is true when calling from command line.
if __name__ == '__main__':

    app = QApplication(sys.argv)
    widget = MainWidget()
    sys.exit(app.exec_())
