from PyQt5.QtWidgets import QComboBox, QLineEdit, QTextEdit

from widgets_generic import TextWidget, MultiLineTextWidget, SelectorWidget


class QLineEditWidget(TextWidget):
    def __init__(self, qlineedit=None):
        self.qlineedit = qlineedit or QLineEdit()
    def get_qt_widget(self):
        return self.qlineedit
    def get_text(self):
        return self.qlineedit.text()
    def set_text(self, new_text):
        self.qlineedit.setText(new_text)
    def set_edit_callback(self, callback):
        # textEdited fires on every keystroke.
        # editingFinished fires when losing focus, but this can be
        # oversensitive when adding/removing elements.
        self.qlineedit.editingFinished.connect(callback)


class QTextEditWidget(MultiLineTextWidget):
    def __init__(self, qtextedit=None):
        self.qtextedit = qtextedit or QTextEdit()
    def get_qt_widget(self):
        return self.qtextedit
    def get_text(self):
        return self.qtextedit.toPlainText()
    def set_text(self, new_text):
        self.qtextedit.setPlainText(new_text)
    def set_edit_callback(self, callback):
        # Note that textChanged responds to not just user edits, but also
        # to clear(), append(), and setText().
        # Take care not to cause an infinite loop or anything silly because
        # of that.
        self.qtextedit.textChanged.connect(callback)
    def accommodate_line_count(self, line_count):
        self.qtextedit.setFixedHeight(min(line_count * 26, 250))


class QTextEditReadOnlyWidget(QTextEditWidget):
    """Sometimes QTextEdit signals are just too hard to work with."""
    def set_edit_callback(self, callback):
        pass


class QComboBoxWidget(SelectorWidget):
    def __init__(self, qcombobox=None):
        self.qcombobox = qcombobox or QComboBox()
    def get_qt_widget(self):
        return self.qcombobox
    def populate_choices(self, choice_text_list):
        self.qcombobox.clear()
        self.qcombobox.addItems(choice_text_list)
    def get_choice(self):
        return self.qcombobox.currentText()
    def set_choice(self, text):
        return self.qcombobox.setCurrentText(text)
    def set_change_callback(self, callback):
        self.qcombobox.activated[str].connect(callback)
