from .sbom_lib import Component, Vulnerability, SAFE_RESOLUTIONS, VALID_GOST
from .tex_utils import protect, b, box, join_multiline, url, ReportColors, in_human, in_small, htmlcolor, ReportColors, seqsplit
from .tex_table import *


def encode_component(c: Component, no_gost: bool = False, shame: bool = False):
    cve_color = ReportColors.GOLD if not c.vulns else ReportColors.HOT_PINK
    src_color = ReportColors.GRAY_BACKGROUND.value
    if shame:
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
        ] if not no_gost else [],
        [
            (ReportColors.GRAY_BACKGROUND.value, box('1.5cm', join_multiline('Глуб.', str(c.depth)+'\\strut{}'), True)),
            multicolumn(3, 'l|', box('7cm', 'Языки: ' + protect(c.langs)), color=ReportColors.GRAY_BACKGROUND.value),
            multicolumn(2, 'c|', box('5cm', join_multiline('Тип: ', protect(c.type_)), True), color=type_color.value),
        ],
        [
            multicolumn(6, '|l|', box('15.5cm', join_multiline(
                box('15cm', 'Источники', True) if any(
                    (c.purl, c.gost_provided_by, c.reference) if not no_gost else (c.purl, c.reference)
                ) else box('15cm', 'Источники отсутствуют!'),
                box('15cm', '\\strut{}$\\cdot$\\,\\seqsplit{' + protect(c.purl) + '}\\quad [PURL]') if c.purl else '',
                box('15cm', '\\strut{}$\\cdot$\\,' + protect(c.gost_provided_by) + '\\quad [PROVIDED\\_BY]') if c.gost_provided_by and not no_gost else '',
                box('15cm', '\\strut{}$\\cdot$\\,' + url(c.reference) + f'\\quad [{c.reference_type}]') if c.reference else '',
            )), color=src_color)
        ],
    ], 6)


def encode_root(root: Component, title: str = 'Корень'):
    return f'''
\\textbf{b(title + ':')} {protect(root.name)}

\\begin{b('itemize')}
    \\item \\textbf{b('Версия:')} {protect(root.version)}
    \\item \\textbf{b('Разработчик:')} {protect(root.manufacturer)}''' + (f'''
    \\item \\textbf{b('Тип компонента:')} {protect(root.type_)}
''' if root.type_ else '') + f'''
\\end{b('itemize')}
'''


def encode_vuln(vuln: Vulnerability, get_component, shame: bool):
    grade = vuln.get_leading_grade()

    components: list[Component] = [get_component(c) for c in vuln.components]
    components_as_text = [
        '\\strut{}$\\cdot$\\,\\seqsplit{' + protect(c.name) + '\\quad [' + protect(c.version)  + ']}' for c in components
    ]

    cve_color = ReportColors.SeverityColor(grade.severity)
    if vuln.verdict_stat in SAFE_RESOLUTIONS:
        cve_color = ReportColors.VulnerabilityStatusColor(vuln.verdict_stat)

    return table([
        [
            multicolumn(2, '|c|', protect(vuln.main_id), color=cve_color),
            multicolumn(2, 'c|', protect(in_human(grade.severity) + ' (' + grade.method + ')'), color=ReportColors.SeverityColor(grade.severity)),
            multicolumn(2, 'c|', protect(grade.score + ' (' + grade.method + ')'), color=ReportColors.SeverityColor(grade.severity)),
        ],
        [
            multicolumn(2, '|c|', column('Имена', *map(in_small, map(protect, vuln.ids_))), color=ReportColors.GRAY_BACKGROUND.value),
            multicolumn(2, 'l|', free_text('0.5\\textwidth', in_small(protect(vuln.desc)))),
            multicolumn(2, 'c|', column('CWEs', *map(protect, map(lambda x: f'CWE-{x}', vuln.cwes))), color=ReportColors.NEUTRAL_RED.value),
        ],

        [
            multicolumn(3, '|c|', free_text('0.4\\textwidth', in_small('\\underline{Рекомендация:} ' + protect(vuln.recommendation))), color=ReportColors.NEUTRAL_RED.value),
            multicolumn(3, 'l|', in_small(free_text('9cm', join_multiline(
                r'{\hfil{}{Затронуты:}\hfil{}}' if any(components_as_text) else 'Затронутые компоненты отсутствуют!',
                *[box('\\linewidth', c) for c in components_as_text]
            ))), color=ReportColors.LOW_ORANGE.value)
        ] if vuln.recommendation else [
            multicolumn(6, '|l|', box('0.95\\textwidth', join_multiline(
                '\\strut{}' + box('0.95\\textwidth', 'Затронуты:', True) if any(components_as_text) else box('15cm', 'Затронутые компоненты отсутствуют!'),
                *[box('0.95\\textwidth', c) for c in components_as_text]
            )), color=ReportColors.LOW_ORANGE.value)
        ],

        [
            multicolumn(4, '|l|', free_text('0.7\\textwidth', 'Комментарий: ' + protect(vuln.verdict_desc)), color=ReportColors.VulnerabilityStatusColor(vuln.verdict_stat)),
            multicolumn(2, 'c|', in_human(vuln.verdict_stat), color=ReportColors.VulnerabilityStatusColor(vuln.verdict_stat)),
        ] if vuln.verdict_stat or vuln.verdict_desc or shame else [],
    ], 6)


ComponentToLine = [
    (
        "Имя компонента",
        lambda c: c.name,
        lambda s: free_text("3cm", in_small(seqsplit(protect(s)))),
        lambda a: True,
        lambda c, a: '' if not c.vulns else (ReportColors.HOT_PINK if (a.shame and c.solved_vulns < c.vulns) else ReportColors.ORANGE).value
    ),
    (
        "Версия",
        lambda c: c.version,
        lambda s: free_text("2cm", in_small(seqsplit(protect(s)))),
        lambda a: True,
        lambda c, a: '' if not c.vulns else (ReportColors.HOT_PINK if (a.shame and c.solved_vulns < c.vulns) else ReportColors.ORANGE).value
    ),
    (
        "Глуб",
        lambda c: c.depth,
        lambda s: str(s),
        lambda a: True,
        lambda c, a: ''
    ),
    (
        "ПА",
        lambda c: c.gost_attack_surface,
        lambda s: s[0] if s in VALID_GOST else '??',
        lambda a: not a.no_gost,
        lambda c, a: ReportColors.GostColor(c.gost_attack_surface)
    ),
    (
        "ФБ",
        lambda c: c.gost_security_function,
        lambda s: s[0] if s in VALID_GOST else '??',
        lambda a: not a.no_gost,
        lambda c, a: ReportColors.GostColor(c.gost_security_function)
    ),
    (
        "CVE",
        lambda c: c.vulns,
        lambda s: str(s),
        lambda a: not a.no_cve,
        lambda c, a: '' if not c.vulns else (ReportColors.HOT_PINK if (a.shame and c.solved_vulns < c.vulns) else ReportColors.ORANGE).value
    ),
    (
        "Тип",
        lambda c: c.type_,
        lambda s: protect(s),
        lambda a: True,
        lambda c, a: ReportColors.BLUE_NOT_AFFECTED.value if c.has_interesting_type else ''
    ),
    (
        "Языки",
        lambda c: c.langs,
        lambda s: free_text("3cm", in_small(protect(s))),
        lambda a: True,
        lambda c, a: ''
    ),
    (
        "Provided By",
        lambda c: c.gost_provided_by or '',
        lambda s: protect(s[:6]) + (r'\dots{}' if len(s) > 6 else ''),
        lambda a: not a.no_gost,
        lambda c, a: ''
    ),
    (
        "Источники",
        lambda c: (c.purl, c.reference),
        lambda s: in_small(box('4cm', join_multiline(
                box('4cm', '\\strut{}$\\cdot$\\,\\seqsplit{' + protect(s[0]) + '}') if s[0] else '',
                box('4cm', '\\strut{}$\\cdot$\\,' + url(s[1])) if s[1] else '', ''
            ))),
        lambda a: True,
        lambda c, a: ReportColors.LOW_ORANGE.value if a.shame and not c.has_proper_src else ''
    ),
]


class ComponentToTable:
    @staticmethod
    def Color(f: tuple, c: Component, a):
        result = f[4](c, a) or ''
        if result:
            return htmlcolor(result)
        return result

    @staticmethod
    def Header(a):
        return [f[0] for f in ComponentToLine if f[3](a)]

    @staticmethod
    def Apply(c: Component, a):
        return [
            ComponentToTable.Color(f, c, a) + f[2](f[1](c)) for f in ComponentToLine if f[3](a)
        ]





