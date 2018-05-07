# The goal of this module is to define just enough of a GUI-widget abstraction
# so that Field classes don't have to assume a particular GUI framework, such
# as Qt.
# This isn't a complete abstraction of the entire GUI though.


class Widget():
    pass

class TextWidget(Widget):
    def get_text(self):
        raise NotImplementedError
    def set_text(self, new_text):
        raise NotImplementedError
    def set_edit_callback(self, callback):
        raise NotImplementedError
    def add_to_container(self, container):
        raise NotImplementedError

class MultiLineTextWidget(TextWidget):
    def accommodate_line_count(self, line_count):
        """Resize the widget or whatever is needed to accommodate
        multiple lines of text."""
        raise NotImplementedError

class SelectorWidget(Widget):
    def populate_choices(self, choice_text_list):
        raise NotImplementedError
    def get_choice(self):
        raise NotImplementedError
    def set_change_callback(self, callback):
        raise NotImplementedError
    def add_to_container(self, container):
        raise NotImplementedError
