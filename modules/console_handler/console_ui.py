from prettytable import PrettyTable, PLAIN_COLUMNS


class ConsoleUI:
    """ Console UI """
    def __init__(self):
        self._start_msg = ''
        self._column = {}
        self._end_msg = ''
        self._columns = []

    def add_column(self, name: str):
        """
        Add column

        :param name: Name of column
        """
        self._column[name] = []
        self._columns.append(name)

    def add_value_to_column(self, name: str, value: str):
        """
        Add value to column

        :param name: Name of column
        :param value: Value to column
        """
        self._column[name].append(value)

    def add_start_msg(self, msg: str):
        """
        Add start message

        :param msg: Start message
        """
        self._start_msg = msg

    def add_end_msg(self, msg):
        """
        Add end message

        :param msg: End message
        """
        self._end_msg = msg

    def print(self):
        """
        Output data to console

        """
        print(self._start_msg)
        pretty_table = PrettyTable(self._columns)
        pretty_table.set_style(PLAIN_COLUMNS)
        temp = list(zip(*[self._column[column] for column in self._columns]))
        pretty_table.add_rows(temp)
        if len(temp) > 0:
            print(pretty_table)
        else:
            print('Nothing found')
        print()
        print(self._end_msg)
