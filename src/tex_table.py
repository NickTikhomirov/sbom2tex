from dataclasses import dataclass
from copy import copy
from enum import Enum

from .tex_utils import cut_text, ReportColors, protect, in_small, b, Г, protect_but_better


@dataclass
class Cell:
    data: str
    #lines: tuple[tuple[int, int]] | None = (,)
    color: ReportColors | None = None
    can_be_huge: bool = False
    small_font: bool = False
    unprotected: bool = False
    pattern: str = ''
    is_multirow: bool = False
    multi_size: int = 0
    bold: bool = False

    def set(self, **kwargs):
        for k, v in kwargs.items():
            if k not in dir(self):
                continue
            self.__setattr__(k, v)
        return self

    def check_huge(self):
        if type(self) != Cell:
            return False
        return self.can_be_huge

    def get_data(self):
        if type(self) != Cell:
            return self
        return self.data



    def __call__(self, new_data: str):
        result = copy(self)
        result.data = new_data
        return result

    def render_classic(self):
        if type(self) != Cell:
            return str(self)

        result = self.data
        if self.unprotected:
            protector = protect_but_better if self.can_be_huge else protect
            result = protector(result)

        if self.bold:
            result = f'\\textbf{b(result)}'

        if self.small_font:
            result = in_small(self.data)

        if self.color is not None:
            result = self.color.htmlcolor() + result

        if self.multi_size:
            multi_instruction = r'\multi' + ('row' if self.is_multirow else 'column') + b(self.multi_size)
            multi_instruction += b('*' if self.is_multirow else self.pattern)
            result = multi_instruction + b(result)

        return result

    def render_longtblr(self):
        if type(self) != Cell:
            return str(self)

        result = self.data
        if self.unprotected:
            protector = protect_but_better if self.can_be_huge else protect
            result = protector(result)

        if self.bold:
            result = f'\\textbf{b(result)}'

        result = r'\strut{}' + b(result)

        args_1 = []
        args_2 = []

        if self.multi_size:
            args_1 += [f"{'r' if self.is_multirow else 'c'}={self.multi_size}"]
            args_2 += ['' if self.is_multirow else self.pattern.replace('|', '')]

        if self.color is not None:
            args_2 += [f"bg={self.color.latex_name()}"]

        cell_instruction = r'\SetCell'
        cell_instruction += Г(','.join(filter(bool, args_1))) if any(args_1) else ''
        cell_instruction += b(','.join(filter(bool, args_2))) if any(args_2) else ''

        if any(args_1 + args_2):
            result = cell_instruction + '  ' + result

        if not self.is_multirow:
            result += '&'.join(' ' * self.multi_size)

        return result


@dataclass
class Line:
    data: list[str | Cell]
    can_break_after: bool = True

    def __call__(self, new_data: str):
        result = copy(self)
        result.data = new_data
        return result

    def end(self):
        result = r'\\ ' if self.can_break_after else r'\\*'
        return result + '\n'


PREMADE_CELL_BREAKABLE = Cell('', can_be_huge=True, small_font=True, unprotected=True)
PREMADE_CELL_GRAY = Cell('', color=ReportColors.GRAY_BACKGROUND)
PREMADE_CELL_BOLD = Cell('', bold=True)


def multirow(size: int, text: str, color: ReportColors = None):
    return Cell(text, color, is_multirow=True, multi_size=size)


def multicolumn(size: int, marker: str, text: str, color: ReportColors = None):
    return Cell(text, color, multi_size=size, pattern=marker)


class TableType(Enum):
    SHORT = 'tabular'
    LONG = 'longtable'
    FLEXIBLE = 'longtblr'

    def get_line_delimeter(self):
        return {
            TableType.SHORT: r'\\ ',
            TableType.LONG: r'\\ ',
            TableType.FLEXIBLE: r'\\* ',
        }.get(self) or r'\\ '

    def get_cell_render(self):
        return {
            TableType.SHORT: Cell.render_classic,
            TableType.LONG: Cell.render_classic,
            TableType.FLEXIBLE: Cell.render_longtblr,
        }.get(self) or Cell.render_classic

    def __call__(self, contents: list[list | tuple | Cell], signature: str | int):
        if type(signature) == int:
            signature = '|' + ('c|' * signature)
        result = r'''
    \begin{''' + self.value + '}{' + signature + r'''}
    \hline
    '''
        render = self.get_cell_render()
        for line in contents:
            if not line: continue
            ranges = []
            if type(line) == tuple:
                ranges, line = line

            if any(Cell.check_huge(i) for i in line):
                cut_vector = [cut_text(Cell.get_data(v), 'Нет данных') if Cell.check_huge(v) else [Cell.get_data(v)] for
                              v in line]
                spread_size = max(map(len, cut_vector))
                for depth in range(spread_size):
                    line_in_spread = []
                    for i, cell in enumerate(cut_vector):
                        data = cell[depth] if depth < len(cell) else ''
                        line_in_spread.append(line[i](data))
                    result += ' & '.join(map(render, line_in_spread)) + r'\\ '
            else:
                result += ' & '.join(map(render, line)) + self.get_line_delimeter()
            if not ranges:
                result += r'\hline '
            else:
                result += ' '.join(r'\cline{' + f'{r[0]}-{r[1]}' + '}' for r in ranges)

        result += r'''
    \end{''' + self.value + '}'

        return result


def column(first: str, *lines: str):
    if len(lines) == 0:
        return ''
    return r'''
\begin{tabular}{c}
''' + ((r'\underline{' + first + r'}: \\') if first else '') + r'''
''' + '\\\\'.join(line for line in lines) + r'''\\
\end{tabular}
'''


def free_text(size: str, text: str):
    return '\\begin{minipage}{' + size + '}\n\\strut{}' + text + '\\strut{}\n\\end{minipage}'
