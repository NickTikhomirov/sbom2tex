import argparse
from itertools import chain
from pathlib import Path
import subprocess

from src import report_boilerplate
from src import tex_utils
from src import sbom_lib
from src import sbom_to_tex
from src import messages
from src import os_helper as cnt


DROP_OBOM = ["operating-system", "container"]
DROP_BUZZ = ["file", "cryptographic-asset"]


def split(array: list, batchsize: int):
    return [array[i: i + batchsize] for i in range(0, len(array), batchsize)]


def argparse_init():
    parser = argparse.ArgumentParser(description='DependencyTrack PDF Report Client', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-i', '--input', type=Path, action='append', nargs='+', help='DependencyTrack Inventory or VDR')
    parser.add_argument('-o', '--output', default='.', type=Path, help='Directory to store result')
    parser.add_argument('--split', type=int, default=0, help='Split threshold (0 for no split, >19 otherwise)')
    parser.add_argument('--provided-by-is-not-interesting', action='store_true', help='By default all "GOST:provided_by" are considered worth mentioning. Use the flag to override.')
    parser.add_argument('--separate-empty-cves', action='store_true', help='Separate CVEs without description to separate section')
    parser.add_argument('--empty-desc', type=str, default='Некоторые инструменты/базы помечают таким образом вышедшие обновления безопасности для компонентов', help='Use with "--separate-empty-cves" to add a section commentary')

    parser.add_argument('--directive-depth', type=int, default=1, help='For ')
    parser.add_argument('-n', '--name', type=str, default='', help='Project main name (for title)')
    parser.add_argument('-s', '--subtitle-size', type=int, default=24, help='Set size for document subtitle font')

    parser.add_argument('-S', '--review-attack-surface', action='count', help='Check CVEs for attack surface to have user reviews ("-R" for "yes", "-RR" for "yes" and "indirect")')

    parser.add_argument('--shame', action='store_true', help='Add color signals related to missing SBoM data')
    parser.add_argument('--add-os-skips', action='store_true', help='Connect all children of "operating-system" to their grandparent nodes. This feature enhances directive dependencies\' listings for OBoMs')
    parser.add_argument('--no-cve', action='store_true', help='Remove CVE section')
    parser.add_argument('--no-gost', action='store_true', help='Remove all GOST properties')
    parser.add_argument('--no-obom', action='store_true', help='Drop all components with types: ' + ', '.join(DROP_OBOM))
    parser.add_argument('--no-buzz', action='store_true', help='Drop all components with types: ' + ', '.join(DROP_BUZZ))
    parser.add_argument('--no-advertisements', action='store_true', help='Disable "tools" subsection from intro section')
    parser.add_argument('-D', '--all-directives', action='store_true', help='Disable "interesting" filter for directive components')
    parser.add_argument('-A', '--all-components', action='store_true', help='Disable "interesting" filter')
    parser.add_argument('-T', '--table-of-components', action='store_true', help='Write components in one huge table')
    parser.add_argument('-x', '--compile-count', type=int, default=3, help='Use this with "--compile" to tamper with amount of compilation iterations (2-3 iterations are perfect, 3 is default)')
    parser.add_argument('--compile', action='store_true', help='Invoke latexmk to compile results')
    parser.add_argument('--use-arial', action='store_true', help='Use Arial font (if you have one on your machine)')

    parser.add_argument('-O', '--opinionated', action='store_true', help='Use author\'s favourite preset')

    add_to_title_help = [
        '"-t t" is reserved for SBoM timestamp',
        '"-t d" is reserved for current date (no time)',
        '"-t s" is reserved for line',
        '"-t r" is reserved -- the flag forces one next "-t" to be right-aligned',
        '"-t N" is reserved for document part number',
        '"-t k" is reserved for document kind (components, vulnerabilities)',
    ]
    parser.add_argument('-t', '--add-to-title', type=str, action='append', help='Additional lines to write on title page. Flag can be used multiple times.' + '\n\t'.join([''] + add_to_title_help))
    return parser.parse_args()


if __name__ == '__main__':
    args = argparse_init()
    possible_directories_or_sboms = list(chain.from_iterable(args.input))
    if not possible_directories_or_sboms:
        print('No input files! Exiting now!')
        exit()

    sbom_files = list(chain.from_iterable(cnt.find_json_files(d) for d in possible_directories_or_sboms))
    if (not args.output) or (args.compile and str(args.output) == '.') or not cnt.is_dir(args.output):
        if dirs := [d for d in possible_directories_or_sboms if cnt.is_dir(d)]:
            args.output = dirs[0]

    args.add_to_title = args.add_to_title or []
    if args.opinionated:
        args.no_cve = False
        args.no_obom = False
        args.no_buzz = True
        if "d" not in args.add_to_title:
            args.add_to_title = ["d"] + args.add_to_title
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

    drop_types = (DROP_OBOM if args.no_obom else []) + (DROP_BUZZ if args.no_buzz else [])
    sbom = sbom_lib.build_sbom_from_files(sbom_files, drop_types, skip_types=["operating-system"] if args.add_os_skips else [])

    grade = ''
    grade_name = ''
    grade_desc = ''
    if args.review_attack_surface:
        types_ = ['yes'] + (['indirect'] if args.review_attack_surface > 1 else [])
        for cmp in sbom.iter_components():
            if cmp.gost_attack_surface in types_:
                cmp.important = True

        grade = sbom.review_percent(lambda c: c.gost_attack_surface in types_)
        grade_name = 'Закрытых уязвимостей на ПА (%)'
        grade_desc = f'Метрика "{grade_name}" засчитывается положительно в случае наличия комментариев и безопасного (False Positive, Not Affected...) статуса. Доля считается по кортежам (CVE, компонент), то есть одна и та же CVE может быть посчитана ' \
                     f'несколько раз, если влияет на разные компоненты, равно как и компонент может быть посчитан несколько раз, если для него найдено несколько CVE. Для максимальной оценки (100%) нужно разобраться со всеми уязвимостями. ' \
                     f'При подсчёте рассматриваются только компоненты с метками {types_} для поля "GOST:attack_surface". '
    grade_vec = tuple(map(tex_utils.protect, (grade, grade_name, grade_desc)))

    evaluator = sbom_lib.ComponentEstimator(args.provided_by_is_not_interesting, args.no_gost, int(args.all_directives) * args.directive_depth, args.all_components, args.shame)

    project_name = sbom.root.name
    out_dir: Path = args.output
    component_filename = out_dir.joinpath(f'report_components')
    files = []
    filenames = []
    quick_open = lambda x: open(x, 'w', encoding='utf-8')
    common_part_builder = report_boilerplate.make_common_builder(sbom, grade_vec, args.no_gost, args.no_advertisements)

    cve_max = 0
    cmp_max = 0

    if not args.split:    # single file
        filenames += [str(out_dir.joinpath(f'report'))]
        files += [quick_open(str(fname) + '.tex') for fname in filenames]
        files += files
        cve_max = cmp_max = -1

    else:
        if len(sbom.vulnerabilities) <= args.split:        # two files: components + cves
            filenames += [component_filename, out_dir.joinpath(f'report_cve')]

        else:                                                # a lot of files
            cve_max = (len(sbom.vulnerabilities) * 1.0 / args.split).__ceil__() if args.split else 1
            cve_filename = lambda i: out_dir.joinpath(f'report_cve_{i}')
            filenames += [component_filename] + [cve_filename(i+1) for i in range(cve_max)]

        files += [quick_open(str(fname) + '.tex') for fname in filenames]

    # report: titles, intros etc
    for i, f in enumerate(files):
        is_cve = i != 0
        variable_subtitles = {
            "N": 'Часть ' + str(i) if i else '',
            "k": 'Список компонентов' if not is_cve else 'Список уязвимостей',
        } if args.split else {
            "N": 'Цельный отчёт',
            "k": 'Список компонентов и уязвимостей',
        }
        title = report_boilerplate.add_title_page(args.name or project_name + '. Отчёт',
                                            [variable_subtitles.get(l) or report_boilerplate.decode_line(l, sbom.timestamp)
                                             for l in args.add_to_title], args.subtitle_size)

        f.write(report_boilerplate.TOP('Arial' if args.use_arial else 'DejaVu Sans'))
        f.write(title)
        message = messages.intro_message(project_name, i, cve_max if is_cve else cmp_max, is_cve)
        f.write(common_part_builder(tex_utils.protect(message)))

        if not args.split:
            break

    # report: prepare components
    encoder = sbom_to_tex.LineRenderer.ForComponents(args)
    table_header = encoder.Header()
    directive = [cmp for cmp in sbom.iter_components() if cmp.depth <= args.directive_depth and evaluator(cmp)]
    transitive = [cmp for cmp in sbom.iter_components() if cmp.depth > args.directive_depth and evaluator(cmp)]
    directive.sort(key=lambda c: c.depth)
    transitive.sort(key=lambda c: c.depth)
    if args.table_of_components:
        files[0].write('\n\\begin{landscape}\n\n')

    # report: print components
    for name, arr in [('Директивные', directive), ('Транзитивные', transitive)]:
        if not arr:
            continue
        files[0].write('\n\\section{' + name + ' зависимости}\n\n')
        if args.table_of_components:
            files[0].write(sbom_to_tex.TableType.LONG(
                [table_header] +
                [encoder(cmp) for cmp in arr],
                encoder.Signature())
            )
        else:
            for cmp in arr:
                files[0].write(sbom_to_tex.encode_component(cmp, args.no_gost, args.shame))
                files[0].write(tex_utils.step())
                files[0].write(tex_utils.step())

    # report: components outro
    if args.table_of_components:
        files[0].write('\n\\end{landscape}\n\n')
    if skipped := evaluator.counted - evaluator.interesting:
        files[0].write('\n\\section{Дополнительные сведения}\n\n')
        files[0].write('\\textit{Было пропущено ' + str(skipped) + ' компонентов, так как они не были сочтены достаточно примечательными для отображения в отчёте. Полные сведения о компонентах доступны в формате SBoM-файла, который рекомендуется запросить у авторов отчёта.}')

    # report: print cves
    vulns = sbom.vulnerabilities
    empty = []  # for empty vulns
    if args.separate_empty_cves:
        vulns = [v for v in vulns if v.desc]
        empty = [v for v in vulns if not v.desc]
    cve_batches = split(vulns, args.split) if args.split else [vulns]
    for batch, file in zip(cve_batches, files[1:]):
        file.write('\n\\section{Уязвимости}\n\n')
        for cve in batch:
            file.write(sbom_to_tex.encode_vuln(cve, sbom.get_or_alias, args.shame))
            file.write(tex_utils.step())
            file.write(tex_utils.step())

    # report: empty cves
    if empty:
        empty_printer = sbom_to_tex.LineRenderer.ForEmptyCVEs(args)
        f = files[-1]
        f.write('\n\\begin{landscape}\n\n')
        f.write('\n\\section{Уязвимости без описания}\n\n')
        if desc := str(args.empty_desc).strip():
            f.write(tex_utils.protect(desc) + '\n\n')
        f.write(sbom_to_tex.TableType.
                LONG([['Уязвимость', 'Критичность', 'Компонент(ы)', 'Комментарий']], '|p[]|p[]|p[]|p[]|'))
        f.write('\n\\end{landscape}\n\n')

    # report: finalize
    for f in files:
        f.write(report_boilerplate.BOTTOM)
        f.close()
        if not args.split:
            break

    # compile
    if args.compile:
        count = args.compile_count
        if not (1 <= count <= 5):
            count = 3
        for filename in filenames:
            cmd = ['latexmk', '-pdfxe', '-interaction=nonstopmode', '-output-directory='+str(args.output)]
            target = [str(filename) + '.tex']
            for i in range(count):
                subprocess.run(cmd + target)
            subprocess.run(['latexmk', '-c'] + target)
