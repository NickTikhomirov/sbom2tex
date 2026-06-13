
from .tex_utils import htmlcolor


def multirow(size: int, text: str, color: str = ''):
    if color:
        text = htmlcolor(color) + text
    return r'\multirow{' + str(size) + '}{*}{' + text + '}'


def multicolumn(size: int, marker: str, text: str, color: str = ''):
    if color:
        text = htmlcolor(color) + text
    return r'\multicolumn{' + str(size) + '}{' + marker + '}{' + text + '}'


def __cell(a: str | tuple[str, str]):
    color = ''
    if type(a) == tuple:
        color, a = a

    if type(a) != str:
        a = str(a)

    if color:
        return htmlcolor(color) + a
    return a


def table(contents: list[list|tuple], signature: str | int, long: bool = False):
    title = 'tabular' if not long else 'longtable'
    if type(signature) == int:
        signature = '|' + ('c|' * signature)
    result = r'''
\begin{''' + title + '}{' + signature + r'''}
\hline
'''
    for line in contents:
        if not line: continue
        ranges = []
        if type(line) == tuple:
            ranges, line = line
        result += ' & '.join(map(__cell, line)) + r'\\ '
        if not ranges:
            result += r'\hline'
        else:
            result += ' '.join(r'\cline{' + f'{r[0]}-{r[1]}' + '}' for r in ranges)
        result += '\n'

    result += r'''
\end{''' + title + '}'

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
