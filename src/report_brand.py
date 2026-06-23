from datetime import datetime

from .sbom_lib import SBoM
from .sbom_to_tex import encode_root
from .tex_table import TableType, multirow, multicolumn
from .tex_utils import protect, box, ReportColors


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


def add_title_page(name: str, lines: list[str], size: int):
    result = r"""
\begin{titlepage} % Suppresses displaying the page number on the title page and the subsequent page counts as page 1

    \thispagestyle{empty}

    \newgeometry{top=20mm,bottom=20mm,left=20mm,right=20mm}
	
\begin{tikzpicture} [overlay,remember picture]
    \draw [line width=0.5mm ] 
($ (current page.north west) + (1cm, -1cm) $)
    rectangle
    ($ (current page.south east) + (-1cm,1cm) $);
\end{tikzpicture}

	

	\vfill

\begin{title_box}
\vspace{0.7cm} % Space between the start of the title and the top of the grey box

\fontsize{30pt}{35pt}\selectfont{}\color{black}{\textsc{""" + protect(name) + r"""}}

\vspace{0.7cm} % Space between the end of the title and the bottom of the grey box
			
\end{title_box}
	
	\text{} % Space between the title box and author information
	
	\parbox[t]{0.93\textwidth}{ % Box to inset this section slightly
		\large % Increase the font size
		{} % Extra space after name"""

    prev = ''
    for line in lines:
        if not line:
            prev = line
            continue
        if line == 's':
            result += r'\hfill\rule{0.2\linewidth}{1pt}' + '\n\n'
            prev = line
            continue
        elif line == 'r':
            result += r'\raggedleft'
            prev = line
            continue

        result += r"""
				\fontsize{""" + str(size) + "pt}{" + str(1.4 * size) + r"""pt}\selectfont{}\color{black} """ + protect(line) + '\n\n'

        if prev == 'r':
            result += r"""\leftskip=0pt \rightskip=0pt \spaceskip=0pt \xspaceskip=0pt		"""

        prev = line

    return result + r"""
	}

	\vfill
	
	\restoregeometry
\end{titlepage}
\newpage

"""


def make_common_builder(sbom: SBoM, grade: tuple[str, str, str] = ('', '', ''), no_gost: bool = False):
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
        [multicolumn(2, '|l|','Языки проекта'), box('7cm', ', '.join(sorted(sbom.all_languages())))],
    ] if not no_gost else []) + ([
        [multicolumn(2, '|l|', grade_name), grade]]
        if grade else []), "|l|c|c|") + r'''

\end{center}

''' + (grade_desc if grade else '') + r'''

''' + (r'''

\subsection{Источники компонентов (GOST:provided\_by)}

\begin{itemize}
''' + '\n'.join(f'    \\item {protect(kv[0])} ({protect(kv[1])} компонентов)' for kv in provided_by.items()) + r'''
\end{itemize}

''' if sbom.get_provided_by() else '')

    if sbom.tools:
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


TOP = lambda font: r'''% !TEX program =XeLaTeX
\documentclass[12pt, a4paper]{article}

\special{dvipdfmx:config C 0x0010} 

\usepackage[utf8]{inputenc}
\usepackage[russian, english]{babel}
\usepackage[table,xcdraw]{xcolor}
\usepackage{anyfontsize}
\usepackage{setspace}
\usepackage{textcomp}
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
 
\usepackage{tikz}
\usetikzlibrary{calc}
\usetikzlibrary{decorations.pathmorphing}

\SetTblrTemplate{head,foot}{empty}
\usepackage{amsmath}
\usepackage{amsfonts}
\usepackage{pdflscape}

\usepackage[hidelinks]{hyperref}

\newtcolorbox{title_box}{enhanced,colback=red!5!white,
colframe=red!75!black,drop lifted shadow=black}

\setmainfont{''' + font + r'''}

''' + '\n'.join(map(ReportColors.to_latex_define, ReportColors)) + r'''

\begin{document}

\selectlanguage{russian}
\fontsize{14pt}{21pt}\selectfont
'''

BOTTOM = '''

\\end{document}
'''

