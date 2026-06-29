from datetime import datetime

from .sbom_lib import SBoM
from .sbom_to_tex import encode_root
from .tex_table import TableType, multirow, multicolumn, PREMADE_CELL_BOLD
from .tex_utils import protect, box, ReportColors
from .title.title import add_title_page


def decode_line(line: str, timestamp: str = None):
    now = str(datetime.now()).split('.')[0]
    timestamp = timestamp or 'Нет данных'
    if line == 't':
        return 'SBoM: ' + timestamp
    if line == 'd':
        return 'Отчёт: ' + now
    if line == 'N':
        return ''
    return line


def make_common_builder(sbom: SBoM, grade: tuple[str, str, str] = ('', '', ''), no_gost: bool = False, no_advertisiments: bool = False):
    grade, grade_name, grade_desc = grade
    provided_by = sbom.get_provided_by()
    tail = r'''

\subsection{Корневой компонент проекта}

''' + encode_root(sbom.root) + r'''

\subsection{Характеристики проекта}

\begin{center}

''' + TableType.SHORT([
        [multicolumn(2, '|l|', 'Число дочерних компонентов'), sbom.len_components()],
        [multicolumn(2, '|l|', 'Максимальная глубина'), max(cmp.depth for cmp in sbom.iter_components())],
        [multicolumn(2, '|l|', 'Число уязвимостей'), sbom.len_vulnerabilities()],
    ] + ([
        (((2, 3),), [multirow(4, 'ПА'), '(yes)', sbom.count_property_by_value('as', 'yes')]),
        (((2, 3),), ['', '(indirect)', sbom.count_property_by_value('as', 'indirect')]),
        (((2, 3),), ['', '(no)', sbom.count_property_by_value('as', 'no')]),
        ['', '(incorrect)', sbom.count_property_by_value('as', 'TODO')],
        (((2, 3),), [multirow(4, 'ФБ'), '(yes)', sbom.count_property_by_value('sf', 'yes')]),
        (((2, 3),), ['', '(indirect)', sbom.count_property_by_value('sf', 'indirect')]),
        (((2, 3),), ['', '(no)', sbom.count_property_by_value('sf', 'no')]),
        ['', '(incorrect)', sbom.count_property_by_value('sf', 'TODO')],
        [multicolumn(2, '|l|','Число компонентов типа "{}container"{}'), sbom.count_containers()],
        [multicolumn(2, '|l|','Языки проекта'), box('7cm', '\\strut{}' + ', '.join(sorted(sbom.all_languages())))],
    ] if not no_gost else []) + ([
        [multicolumn(2, '|l|', grade_name), grade]]
        if grade else []), "|l|c|c|") + r'''

\end{center}

''' + (grade_desc if grade else '')

    if sbom.get_provided_by():
        tail += r'''

\subsection{Источники компонентов (GOST:provided\_by)}

\begin{itemize}
''' + '\n'.join(f'    \\item {protect(kv[0])} ({protect(kv[1])} компонентов)' for kv in provided_by.items()) + r'''
\end{itemize}

'''

    if any(langs := sbom.get_langs()):
        langs = list(map(list, sorted(langs.items(), key=lambda x: x[1], reverse=True)))
        tail += r'''

\subsection{Языки программирования проекта}

При генерации настоящего документа в перечень языков не внедрялось маркеров вида <<Язык неизвестен>> и подобных.
Все позиции в списке взяты из исходных файлов.

Если для какого-либо компонента было указано несколько языков, то он будет посчитан в нескольких строках таблицы. 

''' + TableType.LONG([[PREMADE_CELL_BOLD("Язык"), PREMADE_CELL_BOLD("Кол")]] + langs, 2)

    if sbom.tools and not no_advertisiments:
        tail += r'''

\subsection{Инструменты генерации SBoM}

'''
        for tool in sbom.tools:
            tail += encode_root(tool, 'Инструмент') + '\n\n'

    return lambda identification: r'''
\tableofcontents

\newpage
\section{Общие сведения}

''' + identification + tail


TOP = lambda font: r'''% !TEX program = XeLaTeX
\documentclass[12pt, a4paper]{article}

\usepackage[russian, english]{babel}
\usepackage[table,xcdraw]{xcolor}
\usepackage{multirow}
\usepackage{multicol}
\usepackage{xurl}
\usepackage{fontspec}
\usepackage{longtable}
\usepackage{tabularray}
\usepackage{indentfirst}
\usepackage{seqsplit}
\usepackage{array}
\usepackage[most]{tcolorbox}
\usepackage[a4paper, left=20mm, top=20mm, right=10mm, bottom=20mm]{geometry}
\usepackage{fancyhdr} 
\usepackage{tikz}
\usetikzlibrary{calc}
\usetikzlibrary{decorations.pathmorphing}

\SetTblrTemplate{head,foot}{empty}
\usepackage{pdflscape}

\usepackage[hidelinks]{hyperref}

\newtcolorbox{title_box}{enhanced,colback=red!5!white,
colframe=red!75!black,drop lifted shadow=black}

% переносы и выравнивание:
\tolerance=1
\emergencystretch=\maxdimen
\hyphenpenalty=10000
\hbadness=10000

\setmainfont{''' + font + r'''}

''' + '\n'.join(map(ReportColors.to_latex_define, ReportColors)) + r'''

\begin{document}

\selectlanguage{russian}
\fontsize{14pt}{21pt}\selectfont
'''

BOTTOM = '''

\\end{document}
'''

