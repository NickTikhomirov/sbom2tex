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


def protect(string: str | object):
    string = str(string)
    string = string.replace('\\', '\\textbackslash')
    string = string.replace('~', '\\texttildelow')
    for symbol in '_#$&%"':
        string = string.replace(symbol, '\\' + symbol)
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
    return r'\parbox[t]{' + size + '}{' + text + '}'


def join_multiline(*lines: str):
    return '\\\\'.join(filter(bool, lines))

def step():
    return '\n\\text{}\n'


