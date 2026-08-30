import shlex
import sys
from pathlib import Path
import argparse

from .sbom_lib import DROP_OBOM, DROP_BUZZ


def read_args_from_file(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        flags = ' '.join(f)
        return shlex.split(flags)


def process_flags_with_minus_plus(flags: list[str]):
    if '-+' not in flags:
        return flags

    new_args_raw = []
    is_flag_file = False
    for arg in flags:
        if arg == '-+':
            is_flag_file = True
            continue
        if is_flag_file:
            flags_from_file = read_args_from_file(arg)
            if '-+' in flags_from_file:
                raise RuntimeError(f'Found nested "-+" at file {arg}')
            new_args_raw.extend(flags_from_file)
            is_flag_file = False
            continue
        new_args_raw.append(arg)

    return new_args_raw


def init():
    parser = argparse.ArgumentParser(description='DependencyTrack PDF Report Client', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-i', '--input', type=Path, action='append', nargs='+', help='DependencyTrack Inventory or VDR')
    parser.add_argument('-o', '--output', default='.', type=Path, help='Directory to store result')
    parser.add_argument('--split', type=int, default=0, help='Split threshold (0 for no split, >19 otherwise)')
    parser.add_argument('--provided-by-is-not-interesting', action='store_true', help='By default all "GOST:provided_by" are considered worth mentioning. Use the flag to override.')

    parser.add_argument('--directive-depth', type=int, default=1, help='For ')
    parser.add_argument('-n', '--name', type=str, default='', help='Project main name (for title)')
    parser.add_argument('-s', '--subtitle-size', type=int, default=24, help='Set size for document subtitle font')
    parser.add_argument('--intro-text', type=str, default='', help='Use to override default intro message')

    parser.add_argument('-S', '--review-attack-surface', action='count', help='Check CVEs for attack surface to have user reviews ("-R" for "yes", "-RR" for "yes" and "indirect")')

    parser.add_argument('--shame', action='store_true', help='Add color signals related to missing SBoM data')
    parser.add_argument('--add-os-skips', action='store_true', help='Connect all children of "operating-system" to their grandparent nodes. This feature enhances directive dependencies\' listings for OBoMs')
    parser.add_argument('-N', '--add-name-clusters', action='store_true', help='Adds a new subsection in "Intro" that lists components with same name (something like "uniq -D" in Linux)')
    parser.add_argument('--no-cmp', action='store_true', help='Remove section for components (does not affect "--add-name-clusters")')
    parser.add_argument('--no-cve', action='store_true', help='Remove CVE section')
    parser.add_argument('--no-gost', action='store_true', help='Remove all GOST properties')
    parser.add_argument('--no-obom', action='store_true', help='Drop all components with types: ' + ', '.join(DROP_OBOM))
    parser.add_argument('--no-toc', action='store_true', help='Disable Table of Contents')
    parser.add_argument('--no-buzz', action='store_true', help='Disable ' + ', '.join(DROP_BUZZ))
    parser.add_argument('--fake-aux', action='store_true', help='Generates report.aux sufficient enough for good first-try title (default title is drawn with tikz so .aux is a must)')
    parser.add_argument('--no-advertisements', action='store_true', help='Disable "tools" subsection from intro section')
    parser.add_argument('-D', '--all-directives', action='store_true', help='Disable "interesting" filter for directive components')
    parser.add_argument('-A', '--all-components', action='store_true', help='Disable "interesting" filter')
    parser.add_argument('-T', '--table-of-components', action='store_true', help='Write components in one huge table')
    parser.add_argument('--compile', action='store_true', help='Invoke latexmk to compile results')
    parser.add_argument('-x', '--compile-count', type=int, default=3, help='Use this with "--compile" to tamper with amount of compilation iterations (2-3 iterations are perfect, 3 is default). Advice: with "-x 1" also use "--no-toc" and "--fake-aux"')
    parser.add_argument('--use-arial', action='store_true', help='Use Arial font (if you have one on your machine)')
    parser.add_argument('--enrich-bdu-web', action='count', help='Enrich CVEs with BDU-WEB (FSTEC) based on related CWEs. Use flag twice to take full CWE graph into consideration')

    parser.add_argument('-O', '--opinionated', action='store_true', help='Use author\'s favourite preset')
    #parser.add_argument('-+', dest='include', type=Path, help='Include flags from file')

    add_to_title_help = [
        '"-t t" is reserved for SBoM timestamp',
        '"-t d" is reserved for current date (no time)',
        '"-t s" is reserved for line',
        '"-t r" is reserved -- the flag forces one next "-t" to be right-aligned',
        '"-t N" is reserved for document part number',
        '"-t k" is reserved for document kind (components, vulnerabilities)',
    ]
    parser.add_argument('-t', '--add-to-title', type=str, action='append', help='Additional lines to write on title page. Flag can be used multiple times.' + '\n\t'.join([''] + add_to_title_help))

    return parser.parse_args(process_flags_with_minus_plus(sys.argv[1:]))


def tweak(args):
    args.add_to_title = args.add_to_title or []
    if args.opinionated:
        args.no_obom = False
        args.no_buzz = True
        if "N" not in args.add_to_title and args.split:
            args.add_to_title = ["N"] + args.add_to_title
        if "k" not in args.add_to_title:
            args.add_to_title = ["k"] + args.add_to_title
        args.add_os_skips = True
        args.table_of_components = True
        args.all_directives = True
        args.review_attack_surface = True
        if args.split:
            args.add_to_title = [a for a in args.add_to_title if a != 'N']
        if args.compile_count == 1:
            args.fake_aux = True
            args.no_toc = True

    args.table_of_components = args.table_of_components and not args.no_cmp


def get():
    args = init()
    tweak(args)
    return args

