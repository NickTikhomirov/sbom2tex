

def protect(string: str | object):
    string = str(string)
    string = string.replace('\\', '\\textbackslash')
    string = string.replace('~', '\\texttildelow')
    for symbol in '_#$&%"':
        string = string.replace(symbol, '\\' + symbol)
    return string


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


