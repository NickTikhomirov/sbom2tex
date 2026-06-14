from enum import Enum


class ReportColors(Enum):
    LOW_ORANGE = "FFF2CC"
    ORANGE = "FFD766"
    HOT_PINK = "FF7C80"
    RED = "FF0000"
    WHITE = "FFFFFF"
    BLUE_NOT_AFFECTED = "BDD7EE"
    GREEN_FP = "92D050"
    GRAY_BACKGROUND = 'EFEFEF'
    GOLD = 'FFC90E'
    NEUTRAL_RED = 'F8CBAD'

    def htmlcolor(self):
        return htmlcolor(self.value)

    def latex_name(self):
        return 'bomtex' + self.name.lower()

    def to_latex_define(self):
        return r'\definecolor' + b(self.latex_name()) + b('HTML') + b(self.value)

    def SeverityColor(*val):
        return {
            "low": ReportColors.LOW_ORANGE,
            "medium": ReportColors.ORANGE,
            "high": ReportColors.HOT_PINK,
            "critical": ReportColors.RED,
        }.get(val[-1]) or ReportColors.WHITE

    def VulnerabilityStatusColor(*val):
        return {
            "resolved": ReportColors.BLUE_NOT_AFFECTED,
            "resolved_with_pedigree": ReportColors.BLUE_NOT_AFFECTED,
            "not_affected": ReportColors.BLUE_NOT_AFFECTED,
            "false_positive": ReportColors.GREEN_FP,
            "in_triage": ReportColors.ORANGE,
            "exploitable": ReportColors.HOT_PINK,
        }.get(val[-1]) or ReportColors.HOT_PINK

    def GostColor(*val):
        return {
            'yes': ReportColors.GREEN_FP,
            'indirect': ReportColors.BLUE_NOT_AFFECTED,
            'no': ReportColors.GRAY_BACKGROUND,
        }.get(val[-1]) or ReportColors.HOT_PINK

    def to_float(self):
        hex_ = self.value
        colors: list[str | float | int] = [hex_[0] + hex_[1], hex_[2] + hex_[3], hex_[4] + hex_[5]]
        for i in range(3):
            colors[i] = int(colors[i], 16)
            colors[i] = colors[i] * 1.0 / 255
        return map(str, colors)


def protect(string: str | object):
    string = str(string)
    string = string.replace('\\', '\\textbackslash{}')
    string = string.replace('~', '\\textasciitilde{}')
    string = string.replace('`', '\\textasciigrave{}')
    for symbol in '_#$&%':
        string = string.replace(symbol, '\\' + symbol)
    string = string.replace('"', '"{}')
    return string


def protect_square_brackets(string: str):
    string = string.replace('[', '{}${}[{}${}')
    string = string.replace(']', '{}${}]{}${}')
    return string


def url(string: str | object):
    string = str(string)
    string = string.replace('%', '\\%')
    return '\\url{' + string + '}'


def in_human(s: str):
    """ 'false_positive' to 'False Positive', etc """
    result = ''
    sep = ''
    for word in s.replace('_', ' ').split():
        result += sep
        result += word[0].upper() + word[1:].lower()
        sep = ' '
    return result


def b(s: object):
    return '{' + str(s) + '}'


def Г(s: object):
    return '[' + str(s) + ']'


def box(size: str, text: str, centered: bool=False):
    if centered:
        text = '\\centering{}' + text
    return r'\parbox[m]{' + size + '}{' + text + '}'


def join_multiline(*lines: str):
    return '\\vspace{0.2cm}' + '\\\\'.join(filter(bool, lines)) + '\\strut{}' + '\\vspace{0.2cm}'


def step():
    return '\n\\text{}\n'


def in_small(text: str):
    return '{\\small{}' + text + '}'


def htmlcolor(text: str):
    return '\\cellcolor[HTML]{' + text + "}"


def seqsplit(s: str):
    return '\\seqsplit{' + s + '}'



def split_by_size(line: str, size: int):
    return [line[i:i+size] for i in range(0, len(line), size)]


def cut_text(text: str, default: str):
    text = text.replace('###', '\n\n###').strip()
    paragrahs = text.split('\n\n')
    result = []
    for par in paragrahs:
        if len(par) > 800:
            result.extend(split_by_size(par, 500))
        else:
            result.append(par)
    if len(result) == 0:
        result = [default]
    return result
