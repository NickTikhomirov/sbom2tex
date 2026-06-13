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

    def GostColor(*val):
        return {
            'yes': ReportColors.GREEN_FP.value,
            'indirect': ReportColors.BLUE_NOT_AFFECTED.value,
            'no': ReportColors.GRAY_BACKGROUND.value,
        }.get(val[-1]) or ReportColors.HOT_PINK.value

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


def b(s: str):
    return '{' + s + '}'


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
