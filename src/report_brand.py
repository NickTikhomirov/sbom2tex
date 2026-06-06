from typing import TextIO
from datetime import datetime
from enum import Enum

from .sbom_lib import SBoM
from .sbom_to_tex import encode_root
from .tex_table import table
from .tex_utils import protect


class ReportColors(Enum):
    LOW_ORANGE = "FFF2CC"
    ORANGE = "FFD766"
    HOT_PINK = "FF7C80"
    RED = "FF0000"
    WHITE = "FFFFFF"
    BLUE_NOT_AFFECTED = "BDD7EE"
    GREEN_FP = "92D050"

    def SeverityColor(*val):
        return {
            "low": ReportColors.LOW_ORANGE.value,
            "medium": ReportColors.ORANGE.value,
            "high": ReportColors.HOT_PINK.value,
            "critical": ReportColors.RED.value,
        }.get(val[-1]) or ReportColors.WHITE.value


    def VulnerabilityStatusColor(*val):
        return {
            "resolved": ReportColors.BLUE_NOT_AFFECTED.value,
            "resolved_with_pedigree": ReportColors.BLUE_NOT_AFFECTED.value,
            "not_affected": ReportColors.BLUE_NOT_AFFECTED.value,
            "false_positive": ReportColors.GREEN_FP.value,
            "in_triage": ReportColors.ORANGE.value,
            "exploitable": ReportColors.HOT_PINK.value,
        }.get(val[-1]) or ReportColors.HOT_PINK.value


def decode_line(line: str, timestamp: str = None):
    now = str(datetime.now())
    timestamp = timestamp or 'Нет данных'
    if line == 't':
        return 'SBoM сгенерирован: ' + timestamp
    if line == 'd':
        return 'Отчёт сгенерирован: ' + now
    return line


def add_title_page(f: TextIO, name: str, lines: list[str], protect):
    f.write(r"""
\begin{titlepage} % Suppresses displaying the page number on the title page and the subsequent page counts as page 1
	
	%------------------------------------------------
	%	Grey title box
	%------------------------------------------------
	\text{}

	\vfill

	\colorbox{grey}{
		\parbox[t]{0.93\textwidth}{ % Outer full width box
			\parbox[t]{0.91\textwidth}{ % Inner box for inner right text margin
				\raggedleft % Right align the text
				\fontsize{40pt}{70pt}\selectfont % Title font size, the first argument is the font size and the second is the line spacing, adjust depending on title length
				\vspace{0.7cm} % Space between the start of the title and the top of the grey box
				
				\fontsize{30pt}{35pt}\selectfont{}\color{blue} \textbf{\textsc{""" + protect(name) + r"""}} \\""")

    for line in lines:
        f.write(r"""
				\fontsize{25pt}{35pt}\selectfont{}\color{black} """ + protect(line))

    f.write(r"""				
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
		{} % Extra space after name
		
		\hfill\rule{0.2\linewidth}{1pt}% Horizontal line, first argument width, second thickness
	}

	\vfill
	
\end{titlepage}
\newpage

""")


def make_common_builder(sbom: SBoM):
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
        ['Языки проекта', r'\parbox[t]{7cm}{' + ', '.join(sbom.all_languages()) + '}'],
    ], "|l|c|") + r'''

\end{center}

''' + r'''

\subsection{Источники компонентов (GOST:provided\_by)}

\begin{itemize}
''' + '\n'.join(f'    \\item {protect(kv[0])} ({protect(kv[1])} компонентов)' for kv in sbom.get_provided_by().items()) + r'''
\end{itemize}




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
\usepackage[a4paper, left=30mm, top=20mm, right=10mm, bottom=20mm]{geometry}
 



\usepackage{amsmath}
\usepackage{amsfonts}

\definecolor{grey}{rgb}{0.9,0.9,0.9} % Colour of the box surrounding the title



\setmainfont{Arial}


\begin{document}

\selectlanguage{russian}
\fontsize{14pt}{21pt}\selectfont
'''

BOTTOM = '''

\end{document}
'''

