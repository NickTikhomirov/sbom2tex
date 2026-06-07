
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


def table(contents: list[list], signature: str | int):
    if type(signature) == int:
        signature = '|' + ('c|' * signature)
    result = r'''
\begin{tabular}{''' + signature + r'''}
\hline
'''
    for line in contents:
        result += ' & '.join(map(__cell, line)) + r'\\ \hline' + '\n'

    result += '''
\end{tabular}
'''
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
