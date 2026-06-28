from ..tex_utils import protect

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
				\fontsize{""" + str(size) + "pt}{" + str(1.4 * size) + r"""pt}\selectfont{}\color{black} """ + protect(
            line) + '\n\n'

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
