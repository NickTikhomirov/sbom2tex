from typing import TextIO
from datetime import datetime

from .sbom_lib import SBoM
from .sbom_to_tex import encode_root
from .tex_table import table
from .tex_utils import protect, box, ReportColors, htmlcolor


def decode_line(line: str, timestamp: str = None):
    now = str(datetime.now()).split('.')[0]
    timestamp = timestamp or 'Нет данных'
    if line == 't':
        return 'SBoM: ' + timestamp
    if line == 'd':
        return 'Отчёт: ' + now
    return line


def add_title_page(f: TextIO, name: str, lines: list[str]):
    f.write(r"""
\begin{titlepage} % Suppresses displaying the page number on the title page and the subsequent page counts as page 1
	
	%------------------------------------------------
	%	Grey title box
	%------------------------------------------------
	\text{}

	\vfill

	\colorbox{pnik}{
		\parbox[t]{0.93\textwidth}{ % Outer full width box
			\parbox[t]{0.91\textwidth}{ % Inner box for inner right text margin
				%\raggedleft  Right align the text
				\fontsize{40pt}{70pt}\selectfont % Title font size, the first argument is the font size and the second is the line spacing, adjust depending on title length
				\vspace{0.7cm} % Space between the start of the title and the top of the grey box
				
				\fontsize{30pt}{35pt}\selectfont{}\color{black}{\textsc{""" + protect(name) + r"""}}
				
				\vspace{0.7cm} % Space between the end of the title and the bottom of the grey box
			}
		}
	}
	
	\vfill % Space between the title box and author information
	
	%------------------------------------------------
	%	Author name and information
	%------------------------------------------------
	
	\parbox[t]{0.93\textwidth}{ % Box to inset this section slightly
		\raggedleft % Right align the text
		\large % Increase the font size
		{} % Extra space after name""")

    for line in lines:
        f.write(r"""
				\fontsize{25pt}{35pt}\selectfont{}\color{black} """ + protect(line) + '\n\n\n')

    f.write(r"""
		\hfill\rule{0.2\linewidth}{1pt}% Horizontal line, first argument width, second thickness
	}

	\vfill
	
\end{titlepage}
\newpage

""")


def make_common_builder(sbom: SBoM):
    provided_by = sbom.get_provided_by()
    tail = r'''

\subsection{Корневой компонент проекта}

''' + encode_root(sbom.root) + r'''

\subsection{Характеристики проекта}

\begin{center}

''' + table([
        ['Число дочерних компонентов', sbom.len_components()],
        ['Число уязвимостей', sbom.len_vulnerabilities()],
        ['Число ПА (yes)', sbom.count_property_by_value('as', 'yes')],
        ['Число ПА (indirect)', sbom.count_property_by_value('as', 'indirect')],
        ['Число ПА (no)', sbom.count_property_by_value('as', 'no')],
        ['Число ПА (incorrect)', sbom.count_property_by_value('as', 'TODO')],
        ['Число ФБ (yes)', sbom.count_property_by_value('sf', 'yes')],
        ['Число ФБ (indirect)', sbom.count_property_by_value('sf', 'indirect')],
        ['Число ФБ (no)', sbom.count_property_by_value('sf', 'no')],
        ['Число ФБ (incorrect)', sbom.count_property_by_value('sf', 'TODO')],
        ['Число компонентов типа "{}container"{}', sbom.count_containers()],
        ['Языки проекта', box('7cm', ', '.join(sbom.all_languages()))],
    ], "|l|c|") + r'''

\end{center}

''' + (r'''

\subsection{Источники компонентов (GOST:provided\_by)}

\begin{itemize}
''' + '\n'.join(f'    \\item {protect(kv[0])} ({protect(kv[1])} компонентов)' for kv in provided_by.items()) + r'''
\end{itemize}

''' if sbom.get_provided_by() else '') + r'''


'''

    return lambda identification: r'''
\tableofcontents

\newpage
\section{Общие сведения}

''' + identification + tail


TOP = r'''
% !TEX program =XeLaTeX
\documentclass[12pt, a4paper]{article}


\usepackage[utf8]{inputenc}
\usepackage[russian, english]{babel}
\usepackage[table,xcdraw]{xcolor}
\usepackage{anyfontsize}
\usepackage[hidelinks]{hyperref}
\usepackage{setspace}
\usepackage{textcomp}
\usepackage{multirow}
\usepackage{multicol}
\usepackage{xurl}
\usepackage{fontspec}
\usepackage{longtable}
\usepackage{indentfirst}
\usepackage{seqsplit}
\usepackage[a4paper, left=30mm, top=20mm, right=10mm, bottom=20mm]{geometry}
 



\usepackage{amsmath}
\usepackage{amsfonts}

\definecolor{grey}{rgb}{0.9,0.9,0.9} % Colour of the box surrounding the title

''' + r'\definecolor{pnik}{rgb}{' + ','.join(ReportColors.HOT_PINK.to_float()) + '}' + r'''

\setmainfont{Arial}


\begin{document}

\selectlanguage{russian}
\fontsize{14pt}{21pt}\selectfont
'''

BOTTOM = '''

\end{document}
'''

