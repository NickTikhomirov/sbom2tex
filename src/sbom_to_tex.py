from .sbom_lib import Component, Vulnerability, VALID_GOST
from .tex_utils import protect, b, box, join_multiline, url, in_human, seqsplit
from .tex_table import *





def encode_component(c: Component, no_gost: bool = False, shame: bool = False):
    cve_color = ReportColors.GOLD if not c.vulns else ReportColors.HOT_PINK
    src_color = ReportColors.GRAY_BACKGROUND
    if shame:
        if not c.has_proper_src:
            src_color = ReportColors.ORANGE
        elif not c.purl:
            src_color = ReportColors.LOW_ORANGE
    type_color = ReportColors.GRAY_BACKGROUND if c.type_ != 'container' else ReportColors.BLUE_NOT_AFFECTED

    return TableType.SHORT([
        [
            multicolumn(5, '|l|', box('14cm', join_multiline(protect(c.name), 'Версия: ') + protect(c.version)), color=cve_color),
            Cell(box('1.5cm', join_multiline('CVE', str(c.vulns)), True), color=cve_color)
        ],
        [
            multicolumn(3, '|c|', 'Поверхность атаки: ' + protect(c.gost_attack_surface), ReportColors.GostColor(c.gost_attack_surface)),
            multicolumn(3, '|c|', 'Реализация функций безопасности: ' + protect(c.gost_security_function), ReportColors.GostColor(c.gost_security_function))
        ] if not no_gost else [],
        [
            PREMADE_CELL_GRAY(box('1.5cm', join_multiline('Глуб.', str(c.depth)+'\\strut{}'), True)),
            multicolumn(3, 'l|', box('7cm', 'Языки: ' + protect(c.langs)), color=ReportColors.GRAY_BACKGROUND),
            multicolumn(2, 'c|', box('5cm', join_multiline('Тип: ', protect(c.type_)), True), color=type_color),
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
    style = lambda x: '\\color{red}' if x.important else ''

    components: list[Component] = [get_component(c) for c in vuln.components]
    components_as_text = [
        '\\strut{}$\\cdot$\\,{' + style(c) + '\\seqsplit{' + protect(c.name) + '\\quad [' + protect(c.version) + ']}}' for c in components
    ]

    cve_color = ReportColors.SeverityColor(grade.severity)
    if vuln.is_resolved:
        cve_color = ReportColors.VulnerabilityStatusColor(vuln.verdict_stat)

    cve_full_severity = ' / '.join(filter(bool, (in_human(grade.severity), grade.score)))
    cve_method = grade.method or grade.src
    cve_full_severity += (' (' + cve_method + ')') if cve_method else ''

    return TableType.FLEXIBLE([
        [
            multicolumn(1, '|c|', protect(cve_full_severity), color=ReportColors.SeverityColor(grade.severity)),
            multicolumn(1, 'c|', protect(vuln.main_id), color=cve_color),
        ],
        [
            PREMADE_CELL_BREAKABLE(vuln.desc),
            PREMADE_CELL_GRAY(column('Имена', *map(in_small, map(protect, vuln.ids_)))),
        ],

        [
            multicolumn(2, '|l|', free_text('0.95\\textwidth', in_small('\\underline{Рекомендация:} ' + protect(vuln.recommendation))), color=ReportColors.NEUTRAL_RED),
        ] if vuln.recommendation else [],

        [
            Cell(box('0.7\\textwidth', join_multiline(
                '\\strut{}' + box('0.\\textwidth', 'Затронуты:', True) if any(components_as_text) else 'Затронутые компоненты отсутствуют!',
                *[box('0.7\\textwidth', c) for c in components_as_text]
            )), color=ReportColors.LOW_ORANGE),
            multicolumn(1, 'c|', column('CWEs', *map(protect, map(lambda x: f'CWE-{x}', vuln.cwes))), color=ReportColors.NEUTRAL_RED),
        ],

        [
            multicolumn(1, '|l|', free_text('0.7\\textwidth', 'Комментарий: ' + protect(vuln.verdict_desc)), color=ReportColors.VulnerabilityStatusColor(vuln.verdict_stat)),
            multicolumn(1, 'c|', in_human(vuln.verdict_stat), color=ReportColors.VulnerabilityStatusColor(vuln.verdict_stat)),
        ] if vuln.verdict_stat or vuln.verdict_desc or shame else [],
    ], '|p{0.7\\textwidth}|c|')


ComponentToLine = [
    (
        "Имя компонента",
        lambda c: c.name,
        lambda s: in_small(seqsplit(protect(s))),
        lambda a: True,
        lambda c, a: '' if not c.vulns else (ReportColors.HOT_PINK if (c.important and c.solved_vulns < c.vulns) else ReportColors.ORANGE),
        lambda a: "5cm" if not a.no_gost else '7cm'
    ),
    (
        "Версия",
        lambda c: c.version,
        lambda s: in_small(seqsplit(protect(s))),
        lambda a: True,
        lambda c, a: '' if not c.vulns else (ReportColors.HOT_PINK if (c.important and c.solved_vulns < c.vulns) else ReportColors.ORANGE),
        lambda a: "2cm" if not a.no_gost else '3cm'
    ),
    (
        "Глуб",
        lambda c: c.depth,
        lambda s: str(s),
        lambda a: True,
        lambda c, a: '',
        lambda a: "1cm"
    ),
    (
        "ПА",
        lambda c: c.gost_attack_surface,
        lambda s: s[0] if s in VALID_GOST else '??',
        lambda a: not a.no_gost,
        lambda c, a: ReportColors.GostColor(c.gost_attack_surface),
        lambda a: "0.7cm" if not a.no_gost else ''
    ),
    (
        "ФБ",
        lambda c: c.gost_security_function,
        lambda s: s[0] if s in VALID_GOST else '??',
        lambda a: not a.no_gost,
        lambda c, a: ReportColors.GostColor(c.gost_security_function),
        lambda a: "0.7cm" if not a.no_gost else ''
    ),
    (
        "CVE",
        lambda c: c.vulns,
        lambda s: str(s),
        lambda a: not a.no_cve,
        lambda c, a: '' if not c.vulns else (ReportColors.HOT_PINK if (c.important and c.solved_vulns < c.vulns) else ReportColors.ORANGE),
        lambda a: "1cm"
    ),
    (
        "Тип",
        lambda c: c.type_,
        lambda s: in_small(seqsplit(protect(s))),
        lambda a: True,
        lambda c, a: ReportColors.BLUE_NOT_AFFECTED if c.has_interesting_type else '',
        lambda a: "2cm"
    ),
    (
        "Языки",
        lambda c: c.langs,
        lambda s: free_text("2cm", in_small(protect(s))),
        lambda a: True,
        lambda c, a: '',
        lambda a: "2cm"
    ),
    (
        "Источники",
        lambda c: (c.purl, c.reference, c.gost_provided_by or ''),
        lambda s: in_small(box("8cm", join_multiline(
                ('\\strut{}$\\cdot$\\,' + protect(s[2])) if s[2] else '',
                ('\\strut{}$\\cdot$\\,\\seqsplit{' + protect(s[0]) + '}') if s[0] else '',
                ('\\strut{}$\\cdot$\\,' + url(s[1])) if s[1] else '',
            ))),
        lambda a: True,
        lambda c, a: ReportColors.LOW_ORANGE if a.shame and not c.has_proper_src else '',
        lambda a: '8cm'
    ),
]


class ComponentToTable:
    @staticmethod
    def Color(f: tuple, c: Component, a):
        result = f[4](c, a) or ''
        if result:
            return result.htmlcolor()
        return result

    @staticmethod
    def Header(a):
        return [f[0] for f in ComponentToLine if f[3](a)]

    @staticmethod
    def Apply(c: Component, a):
        return [
            ComponentToTable.Color(f, c, a) + f[2](f[1](c)) for f in ComponentToLine if f[3](a)
        ]

    @staticmethod
    def Signature(a):
        result = []
        for f in ComponentToLine:
            span = f[5](a)
            if span:
                result += ['p' + b(span)]
        return '|' + '|'.join(result) + '|'






