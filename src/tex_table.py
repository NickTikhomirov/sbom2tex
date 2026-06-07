
def htmlcolor(text: str):
    return '\\cellcolor[HTML]{' + text + "}"


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

