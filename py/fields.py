from collections import OrderedDict
import math
import struct

from exceptions import FieldSpecError


class Field():

    # Be able to look up fields by key.
    field_lookup = dict()

    # Values for all fields.
    # Example structure; careful with arrays:
    # self.values = dict(
    #     course_id=6, racer_array_element_count=30,
    #     racer_array=[
    #         dict(is_human=1, machine_id=25),
    #         dict(is_human=0, machine_id=7),
    #         ...
    #     ], ...
    # )
    # It's an ordered dict to make outputting values to GCI easier.
    values = OrderedDict()

    # This is handy when evaluating expressions that use field values.
    leaf_fields_with_values = set()

    def __init__(self, spec):
        # By reading fields in from a CSV, each possible attribute at least
        # gets an empty string. So that's how we check for a missing attribute.
        if spec['key'] == '':
            raise FieldSpecError("One of the fields is missing a key.")
        self.key = spec['key']

        if spec['label'] == '':
            raise FieldSpecError(f"Field '{self.key}' is missing a label.")
        self.label = spec['label']

        self.field_lookup[self.key] = self

        if spec['parent'] == '':
            self.parent = None
        else:
            if spec['parent'] not in self.field_lookup:
                raise FieldSpecError(
                    f"Field '{self.key}' can't find its parent, which is"
                    f" specified as '{spec['parent']}'.")
            self.parent = self.field_lookup[spec['parent']]
            self.parent.add_child(self)

        if spec['condition'] == '':
            self.condition = None
        else:
            self.condition = spec['condition']

    @classmethod
    def reset_field_structures(cls):
        cls.field_lookup.clear()
        cls.values.clear()
        cls.leaf_fields_with_values.clear()

    def read_value_from_gci(self, values_dict):
        raise NotImplementedError

    def condition_met(self):
        """Some fields have a condition (based on previous fields) on whether
        they're present in the GCI or not. Other fields are always present."""
        if self.condition:
            condition_value = self.evaluate_using_field_values(self.condition)
            if type(condition_value) != bool:
                raise ValueError(
                    "Field condition didn't evaluate as a bool:"
                    f" {self.condition}")
            return condition_value
        else:
            return True

    def value_to_bits(self, value):
        """Return an iterable of bit strings ('0' or '1')."""
        raise NotImplementedError

    def value_to_widget(self):
        """Fill the field's widget text with the field's current value."""
        raise NotImplementedError

    def get_value(self):
        """
        Get the value, accounting for the currently selected array indices,
        if applicable.
        Return None if no value is available.
        """
        if self.parent:
            # Recurse up the hierarchy
            if isinstance(self.parent, ArrayField):
                parent_value_dict = self.parent.get_value_at_current_index()
            else:
                parent_value_dict = self.parent.get_value()

            if parent_value_dict is None:
                return None
            else:
                return parent_value_dict.get(self.key)
        else:
            return self.values.get(self.key)

    def set_value(self, new_value):
        if self.parent:
            # Recurse up the hierarchy
            if isinstance(self.parent, ArrayField):
                parent_value_dict = self.parent.get_value_at_current_index()
            else:
                parent_value_dict = self.parent.get_value()
            parent_value_dict[self.key] = new_value
        else:
            self.values[self.key] = new_value

    @classmethod
    def evaluate_using_field_values(cls, expression_str):
        # We'll eval() the expression using the field values as the
        # global namespace: <field key> = <field value>
        eval_globals = dict([
            (key, cls.field_lookup[key].get_value())
            for key in cls.leaf_fields_with_values
        ])
        return eval(expression_str, eval_globals)

    @classmethod
    def bits_to_bytes(cls, bits):
        current_byte_bits = []
        byte_array = []
        for bit in bits:
            current_byte_bits.append(bit)
            if len(current_byte_bits) == 8:
                byte_array.append(cls.eight_bits_to_byte(current_byte_bits))
                current_byte_bits = []
        # Add remaining bits, if any
        if current_byte_bits:
            # Pad with 0s on right to get 8 bits total
            current_byte_bits += [0]*(8 - len(current_byte_bits))
            byte_array.append(cls.eight_bits_to_byte(current_byte_bits))
        return byte_array

    @staticmethod
    def bytes_to_bits(byte_array):
        for byte in byte_array:
            byte_as_binary_str = format(byte, f'08b')
            for bit in byte_as_binary_str:
                yield bit

    @staticmethod
    def eight_bits_to_byte(bit_list):
        byte_binary_str = ''.join([str(bit) for bit in bit_list])
        return int(byte_binary_str, base=2)


class ValueField(Field):

    def __init__(self, spec, value_text_widget):
        super().__init__(spec)

        if spec['bits'] == '':
            raise FieldSpecError(
                f"Field '{self.key}' doesn't specify a number of bits.")

        if not spec['bits'].isnumeric():
            raise FieldSpecError(
                f"Field '{self.key}' doesn't have an integer number of"
                f" bits: {spec['bits']}")

        self.bit_count = int(spec['bits'])
        if self.bit_count < 1:
            raise FieldSpecError(
                f"Field '{self.key}' has {self.bit_count} bits."
                " The number should be positive.")

        self.value_widget = value_text_widget
        self.value_widget.set_edit_callback(self.widget_to_value)

    def value_to_str(self, value):
        """Return a string to display in a GUI widget."""
        raise NotImplementedError

    def value_to_widget(self):
        value_str = self.value_to_str(self.get_value())
        self.value_widget.set_text(value_str)

    def read_value_from_gci(self, values_dict, bit_generator):
        if not self.condition_met():
            values_dict[self.key] = None
            return

        bits = bit_generator(self.bit_count)
        values_dict[self.key] = self.bits_to_value(bits)

        self.leaf_fields_with_values.add(self.key)

    def str_to_value(self, text):
        """Convert text representation (for widgets) to an internal value.
        May raise ValueError."""
        raise NotImplementedError

    def widget_to_value(self):
        """Update the field's current value according to the field's widget
        text."""
        text = self.value_widget.get_text()
        try:
            value_parsed_from_widget = self.str_to_value(text)
        except ValueError:
            # Widget's value is invalid. Don't change internal value.
            pass
        else:
            # Widget's value is valid. Set internal value.
            self.set_value(value_parsed_from_widget)

        # Regardless of outcome, we want to go in reverse too: value to widget.
        # If widget's value was invalid, this reverts the widget to the last
        # valid value.
        # If widget's value was valid, this ensures the widget text format is
        # consistent. e.g. if this were a float field, the user might not
        # necessarily type in a value which can be expressed exactly using a
        # float, so the internal value gets rounded off to the nearest valid
        # float value. We want to display this rounded-off internal value for
        # accuracy.
        self.value_to_widget()


class IntField(ValueField):

    def bits_to_value(self, bits):
        binary_str = ''.join([str(bit) for bit in bits])
        return int(binary_str, base=2)

    def value_to_bits(self, value):
        if value is None:
            return []

        return format(value, f'0{self.bit_count}b')

    def value_to_str(self, value):
        if value is None:
            return ""
        return str(value)

    def str_to_value(self, text):
        value = int(text)
        max_value = (2 ** self.bit_count) - 1
        if value < 0 or value > max_value:
            raise ValueError(
                f"Got a value which is out of the valid 0-{max_value} range:"
                f" {value}")
        return value


class FloatField(ValueField):

    def __init__(self, spec, value_text_widget):
        super().__init__(spec, value_text_widget)
        if self.bit_count != 32:
            raise FieldSpecError(
                f"Float field '{self.key}' has {self.bit_count} bits."
                " We only support 32 bit floats.")

    def bits_to_value(self, bits):
        bytes_obj = bytes(self.bits_to_bytes(bits))
        return struct.unpack('!f', bytes_obj)[0]

    def value_to_bits(self, value):
        if value is None:
            return []

        byte_iterable = struct.pack('!f', value)
        bit_list = [
            str(bit) for bit in self.bytes_to_bits(byte_iterable)]
        return bit_list

    def value_to_str(self, value):
        if value is None:
            return ""
        # Up to 10 decimal places
        return str(round(value, 10))

    def str_to_value(self, text):
        float_value = float(text)

        # Round to the nearest 32-bit float by packing and unpacking
        try:
            bytes_obj = struct.pack('!f', float_value)
        except OverflowError:
            raise ValueError(f"Float is too large for 32 bits: {float_value}")
        float_value = struct.unpack('!f', bytes_obj)[0]
        return float_value


class HexField(ValueField):

    def bits_to_value(self, bits):
        return self.bits_to_bytes(bits)

    def value_to_bits(self, value):
        if value is None:
            return []

        # value is a byte array
        bit_generator = self.bytes_to_bits(value)
        try:
            output_bits = [next(bit_generator) for i in range(self.bit_count)]
        except StopIteration:
            raise ValueError("Not enough bits in '{self.key}' value.")
        return output_bits

    def value_to_str(self, value):
        """Take an array of byte-integers,
        and return something like: 'A0 87 F3 C4  29 7B FF 6E\n13 DA'"""
        if value is None:
            return ""

        # Write 16 bytes per line
        lines = []
        current_line_bytes = []
        for byte in value:
            current_line_bytes.append(byte)
            if len(current_line_bytes) == 16:
                lines.append(self.sixteen_bytes_to_hex_str(current_line_bytes))
                current_line_bytes = []
        # Write the last partial line, if any
        if current_line_bytes:
            lines.append(self.sixteen_bytes_to_hex_str(current_line_bytes))

        return '\n'.join(lines)

    def str_to_value(self, text):
        """We expect something like: 'A0 87 F3 C4  29 7B FF 6E\n13 DA'
        And want to turn that into an array of byte-integers."""
        # Get whitespace-separated tokens. Each token is taken to be a
        # byte value in hex.
        byte_hex_strs = text.split()
        if len(byte_hex_strs) != math.ceil(self.bit_count / 8):
            raise ValueError("The hex is too long or too short for this field")
        byte_values = []
        for s in byte_hex_strs:
            byte_value = int(s, base=16)
            if byte_value < 0 or byte_value > 255:
                raise ValueError(
                    "Got a byte which is out of the valid 0-255 range:"
                    f" {byte_value}")
            byte_values.append(byte_value)
        return byte_values

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


class LongHexField(HexField):

    def __init__(self, spec, value_text_widget):
        super().__init__(spec, value_text_widget)

        line_count = math.ceil(self.bit_count / (8*16))
        self.value_widget.accommodate_line_count(line_count)


class ContainerField(Field):

    def __init__(self, spec):
        super().__init__(spec)

        self.children = []

    def add_child(self, child_field):
        self.children.append(child_field)

    def value_to_widget(self):
        # Update all the widgets within this array.
        for child_field in self.children:
            child_field.value_to_widget()


class ArrayField(ContainerField):

    def __init__(
            self, spec, index_selector_widget):
        super().__init__(spec)

        if spec['length'] == '':
            raise FieldSpecError(
                f"Field '{self.key}' doesn't specify an array length.")
        self.length_expr = spec['length']

        # Dropdown or similar widget to change the array index.
        self.index_widget = index_selector_widget
        self.index_widget.set_change_callback(self.value_to_widget)

    def read_value_from_gci(self, values_dict, bit_generator):
        if not self.condition_met():
            values_dict[self.key] = None
            return

        array_length = self.evaluate_using_field_values(self.length_expr)
        if type(array_length) != int:
            raise ValueError(
                "Array length didn't evaluate as an int: {self.length_expr}")

        values_dict[self.key] = []
        for i in range(array_length):
            # dict of items in this array element.
            element_values = OrderedDict()
            # Append the dict to the values structure first...
            values_dict[self.key].append(element_values)
            # ...then start filling in the dict. This is necessary because
            # later children might depend on the values of earlier
            # children.
            for child_field in self.children:
                child_field.read_value_from_gci(element_values, bit_generator)

    def value_to_bits(self, value):
        if value is None:
            return []

        output_bits = []
        for element_dict in value:
            # We assume this is an OrderedDict.
            for child_key, child_value in element_dict.items():
                child_field = self.field_lookup[child_key]
                output_bits.extend(child_field.value_to_bits(child_value))
        return output_bits

    def get_current_index(self):
        index_text = self.index_widget.get_choice()
        if index_text == '':
            # We must be in the middle of initializing. We should be
            # currently initializing the latest added array element,
            # so we want to use values from that element.
            element_count_so_far = len(self.get_value())
            return element_count_so_far - 1
        else:
            return int(index_text)

    def get_value_at_current_index(self):
        value = self.get_value()
        if value is None:
            return None
        else:
            return value[self.get_current_index()]

    def update_index_choices(self):
        value = self.get_value()
        if value is None:
            self.index_widget.populate_choices([])
        else:
            array_length = len(value)
            self.index_widget.populate_choices(
                [str(i) for i in range(array_length)])


class DictField(ContainerField):

    def __init__(self, spec):
        super().__init__(spec)

    def read_value_from_gci(self, values_dict, bit_generator):
        if not self.condition_met():
            values_dict[self.key] = None
            return

        # dict of child items.
        values_dict[self.key] = OrderedDict()
        for child_field in self.children:
            child_field.read_value_from_gci(
                values_dict[self.key], bit_generator)

    def value_to_bits(self, value):
        if value is None:
            return []

        output_bits = []
        # We assume this is an OrderedDict.
        for child_key, child_value in value.items():
            child_field = self.field_lookup[child_key]
            output_bits.extend(child_field.value_to_bits(child_value))
        return output_bits
