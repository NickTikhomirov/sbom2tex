
def multirow(size: int, marker: str, text: str):
    return r'\multirow{' + str(size) + '}{' + marker +'}{' + text + '}'


def multicolumn(size: int, text: str):
    return r'\multicolumn{' + str(size) + '}{*}{' + text + '}'


def table(contents: list[list], signature: str | int):
    if type(signature) == int:
        signature = '|' + ('c|' * signature)
    result = r'''
\begin{tabular}{''' + signature + r'''}
\hline
'''
    for line in contents:
        result += ' & '.join(map(str, line)) + r'\\ \hline' + '\n'

    result += '''
\end{tabular}
'''
    return result

