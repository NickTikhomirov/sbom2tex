from .sbom_lib import Component
from .tex_utils import protect, b



def encode_root(root: Component):
    return f'''
\\textbf{b('Корень:')} {protect(root.name)}

\\begin{b('itemize')}
    \\item \\textbf{b('Версия:')} {protect(root.version)}
    \\item \\textbf{b('Разработчик:')} {protect(root.manufacturer)}''' + (f'''
    \\item \\textbf{b('Тип компонента:')} {protect(root.type_)}
''' if root.type_ else '') + f'''
\\end{b('itemize')}
'''



