import os


def exists(s):
    s = str(s)
    return os.path.exists(s)


def is_dir(s):
    s = str(s)
    return os.path.isdir(s) and exists(s)


def is_file(s):
    s = str(s)
    return os.path.isfile(s)


def is_sbom(s):
    file = os.path.realpath(s)
    return exists(s) and is_file(s) and any((str(file).endswith(ext) for ext in ['.json', '.sbom', '.cdx']))


def is_tex(s):
    file = os.path.realpath(s)
    return exists(s) and is_file(s) and any((str(file).endswith(ext) for ext in ['.tex']))


def find_json_files(path):
    if is_sbom(path):
        return [path]
    if not is_dir(path):
        return []
    all_files = [os.path.join(path, item) for item in os.listdir(path)]
    return [f for f in all_files if is_sbom(f)]



