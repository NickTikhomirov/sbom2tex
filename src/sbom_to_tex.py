from .sbom_lib import Component
from .tex_utils import protect, b, box, join_multiline, url, ReportColors
from .tex_table import *


def encode_component(c: Component):
    cve_color = ReportColors.GOLD if not c.vulns else ReportColors.HOT_PINK
    src_color = ReportColors.GRAY_BACKGROUND.value
    if not c.has_proper_src:
        src_color = ReportColors.ORANGE.value
    elif not c.purl:
        src_color = ReportColors.LOW_ORANGE.value
    type_color = ReportColors.GRAY_BACKGROUND if c.type_ != 'container' else ReportColors.BLUE_NOT_AFFECTED

    return table([
        [
            multicolumn(5, '|l|', box('14cm', join_multiline(protect(c.name), 'Версия: ') + protect(c.version)), color=cve_color.value),
            (cve_color.value, box('1.5cm', join_multiline('CVE', str(c.vulns)), True))
        ],
        [
            multicolumn(3, '|c|', 'Поверхность атаки: ' + protect(c.gost_attack_surface), ReportColors.GostColor(c.gost_attack_surface)),
            multicolumn(3, '|c|', 'Реализация функций безопасности: ' + protect(c.gost_security_function), ReportColors.GostColor(c.gost_security_function))
        ],
        [
            (ReportColors.GRAY_BACKGROUND.value, box('1.5cm', join_multiline('Глуб.', str(c.depth)+'\\strut{}'), True)),
            multicolumn(3, 'l|', box('7cm', 'Языки: ' + protect(c.langs)), color=ReportColors.GRAY_BACKGROUND.value),
            multicolumn(2, 'c|', box('5cm', join_multiline('Тип: ', protect(c.type_)), True), color=type_color.value),
        ],
        [
            multicolumn(6, '|l|', box('15.5cm', join_multiline(
                box('15cm', 'Источники', True) if any((c.purl, c.gost_provided_by, c.reference)) else box('15cm', 'Источники отсутствуют!'),
                box('15cm', '\\strut{}$\\cdot$\\,' + protect(c.purl) + '\\quad [PURL]') if c.purl else '',
                box('15cm', '\\strut{}$\\cdot$\\,' + protect(c.gost_provided_by) + '\\quad [PROVIDED\\_BY]') if c.gost_provided_by else '',
                box('15cm', '\\strut{}$\\cdot$\\,' + url(c.reference) + f'\\quad [{c.reference_type}]') if c.reference else '',
            )), color=src_color)
        ],
    ], 6)


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



