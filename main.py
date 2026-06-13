import argparse
from pathlib import Path

from src import report_brand
from src import tex_utils
from src import sbom_lib
from src import sbom_to_tex


DROP_OBOM = ["operating-system", "container"]
DROP_BUZZ = ["file", "cryptographic-asset"]


def split(array: list, batchsize: int):
    return [array[i: i + batchsize] for i in range(0, len(array), batchsize)]


def argparse_init():
    parser = argparse.ArgumentParser(description='DependencyTrack PDF Report Client')
    parser.add_argument('-i', '--input', type=Path, action='append', help='DependencyTrack Inventory or VDR')
    parser.add_argument('-o', '--output', default='.', type=Path, help='Directory to store result')
    #parser.add_argument('-c', '--consult', type=str, default='', help='Enrich report with data from another SBoM file (without actually merging it)')
    parser.add_argument('--split', type=int, default=0, help='Split threshold (0 for no split, >19 otherwise)')
    parser.add_argument('--provided-by-is-not-interesting', action='store_true', help='For now all "GOST:provided_by" are considered worth mentioning. Use the flag to override.')

    parser.add_argument('--introspect-depth', type=int, default=1, help='For ')
    parser.add_argument('-n', '--name', type=str, default='', help='Project main name (for title)')
    parser.add_argument('-s', '--subtitle-size', type=int, default=24, help='Set size for document subtitle font')

    parser.add_argument('-S', '--review-attack-surface', action='count', help='Check CVEs for attack surface to have user reviews ("-R" for "yes", "-RR" for "yes" and "indirect")')

    parser.add_argument('--shame', action='store_true', help='Add color signals related to missing SBoM data')
    parser.add_argument('--add-os-skips', action='store_true', help='Connect all children of "operating-system" to their grandparent nodes. This feature enhances directive dependencies\' listings for OBoMs')
    parser.add_argument('--no-cve', action='store_true', help='Remove CVE section')
    parser.add_argument('--no-gost', action='store_true', help='Remove all GOST properties')
    parser.add_argument('--no-obom', action='store_true', help='Drop all components with types: ' + ', '.join(DROP_OBOM))
    parser.add_argument('--no-buzz', action='store_true', help='Drop all components with types: ' + ', '.join(DROP_BUZZ))
    parser.add_argument('-D', '--all-directives', action='store_true', help='Disable "interesting" filter for directive components')
    parser.add_argument('-A', '--all-components', action='store_true', help='Disable "interesting" filter')
    parser.add_argument('-T', '--table-of-components', action='store_true', help='Write components in one huge table')

    parser.add_argument('-O', '--opinionated', action='store_true', help='Use author\'s favourite preset')

    add_to_title_help = [
        '"-t t" is reserved for SBoM timestamp'
        '"-t d" is reserved for current date (no time)'
        '"-t s" is reserved for line'
        '"-t r" is reserved -- the flag forces one next "-t" to be right-aligned'
        '"-t N" is reserved for document part number'
    ]
    parser.add_argument('-t', '--add-to-title', type=str, action='append', help='Additional lines to write on title page. Flag can be used multiple times.' + '\n\t'.join([''] + add_to_title_help))
    return parser.parse_args()


if __name__ == '__main__':
    args = argparse_init()

    if not args.input:
        exit()

    args.add_to_title = args.add_to_title or []
    if args.opinionated:
        args.no_cve = False
        args.no_obom = False
        args.no_buzz = True
        args.split = 100
        if "d" not in args.add_to_title:
            args.add_to_title = ["d"] + args.add_to_title
        if "N" not in args.add_to_title:
            args.add_to_title = ["N"] + args.add_to_title
        #args.ignore_obom_depth = True
        args.add_os_skips = True
        args.table_of_components = True
        args.all_directives = True
        args.review_attack_surface = True

    evaluator = sbom_lib.ComponentEstimator(args.provided_by_is_not_interesting, args.no_gost, args.shame)

    drop_types = (DROP_OBOM if args.no_obom else []) + (DROP_BUZZ if args.no_buzz else [])
    sbom = sbom_lib.build_sbom_from_files(args.input, drop_types, skip_types=["operating-system"] if args.add_os_skips else [])

    if args.review_attack_surface:
        types_ = ['yes'] + (['indirect'] if args.review_attack_surface > 1 else [])
        grade = sbom.review_percent(lambda c: c.gost_attack_surface in types_)
        grade_name = 'Закрытых уязвимостей на ПА (%)'
        grade_desc = f'Метрика "{grade_name}" засчитывается положительно в случае наличия комментариев и безопасного (False Positive, Not Affected...) статуса. Доля считается по кортежам (CVE, компонент), то есть одна и та же CVE может быть посчитана ' \
                     f'несколько раз, если влияет на разные компоненты, равно как и компонент может быть посчитан несколько раз, если для него найдено несколько CVE. Для максимальной оценки (100%) нужно разобраться со всеми уязвимостями. ' \
                     f'При подсчёте рассматриваются только компоненты с метками {types_} для поля "GOST:attack_surface". '
    else:
        grade = ''
        grade_name = ''
        grade_desc = ''

    grade_vec = tuple(map(tex_utils.protect, (grade, grade_name, grade_desc)))

    out_dir: Path = args.output
    component_filename = out_dir.joinpath(f'report_components')
    files = []
    filenames = []
    quick_open = lambda x: open(x, 'w', encoding='utf-8')
    common_part_builder = report_brand.make_common_builder(sbom, grade_vec)

    common_desc_sbom = lambda i: 'Это отчёт о компонентах проекта ' + args.name + '. Сведения об уязвимостях приведены в отдельном отчёте. Разделение отчётов было осуществлено для повышения читаемости.'
    common_desc_cve  = lambda i: 'Это отчёт о уязвимостях проекта ' + args.name + '. Сведения об компонентах приведены в отдельном отчёте. Разделение отчётов было осуществлено для повышения читаемости.'

    if not args.split:    # single file
        filenames += [str(out_dir.joinpath(f'report'))]
        files += [quick_open(str(fname) + '.tex') for fname in filenames]
        files += files
        common = lambda i: common_part_builder(tex_utils.protect('Это общий (цельный, без разделения на части) отчёт по проекту, содержащий сведения о проекте ' + args.name + ' -- его компонентах и уязвимостях.'))

    else:
        if len(sbom.vulnerabilities) <= args.split:        # two files: components + cves
            filenames += [component_filename, out_dir.joinpath(f'report_cve')]

        else:                                                # a lot of files
            report_count = (len(sbom.vulnerabilities) * 1.0 / args.split).__ceil__() if args.split else 1
            cve_filename = lambda i: out_dir.joinpath(f'report_cve_{i}')
            filenames += [component_filename] + [cve_filename(i+1) for i in range(report_count)]
            common_desc_cve = lambda i: 'Это отчёт о уязвимостях проекта ' + args.name + f' (файл {i} из {report_count}). Сведения об компонентах приведены в отдельном отчёте. Разделение отчётов было осуществлено для повышения читаемости.'

        files += [quick_open(str(fname) + '.tex') for fname in filenames]
        common = lambda i: common_part_builder(tex_utils.protect(
            common_desc_sbom(i)
            if i == 0 else
            common_desc_cve(i)
        ))

    for i, f in enumerate(files):
        f.write(report_brand.TOP)
        if i != 0 or not args.split:
            title_name = args.name or 'Отчёт об уязвимостях'
        else:
            title_name = args.name or 'Отчёт о компонентах'
        report_brand.add_title_page(f, title_name, [report_brand.decode_line(l, sbom.timestamp) if i == 0 or l != 'N' else 'Часть ' + str(i) for l in args.add_to_title], args.subtitle_size)

        f.write(common(i))

        if not args.split:
            break

    encoder = sbom_to_tex.ComponentToTable
    table_header = encoder.Header(args)
    if args.table_of_components:
        files[0].write('\n\\begin{landscape}\n\n')
    files[0].write('\n\\section{Директивные зависимости}\n\n')
    if args.table_of_components:
        files[0].write(sbom_to_tex.table(
            [table_header] +
            [encoder.Apply(cmp, args) for cmp in sbom.iter_components() if cmp.depth <= args.introspect_depth and evaluator(cmp)],
            len(table_header), True)
        )

    else:
        for cmp in sbom.iter_components():
            if cmp.depth > args.introspect_depth:
                continue
            if not args.all_components and not evaluator(cmp):
                continue

            files[0].write(sbom_to_tex.encode_component(cmp, args.no_gost, args.shame))
            files[0].write(tex_utils.step())
            files[0].write(tex_utils.step())

    files[0].write('\n\\section{Транзитивные зависимости}\n\n')
    if args.table_of_components:
        files[0].write(sbom_to_tex.table(
            [table_header] +
            [encoder.Apply(cmp, args) for cmp in sbom.iter_components() if cmp.depth > args.introspect_depth and evaluator(cmp)],
            len(table_header), True)
        )
    else:
        for cmp in sbom.iter_components():
            if cmp.depth > args.introspect_depth:
                if not args.all_components and not args.all_directives and not evaluator(cmp):
                    continue
                files[0].write(sbom_to_tex.encode_component(cmp, args.no_gost, args.shame))
                files[0].write(tex_utils.step())
                files[0].write(tex_utils.step())

    if args.table_of_components:
        files[0].write('\n\\end{landscape}\n\n')

    if skipped := evaluator.counted - evaluator.interesting:
        files[0].write('\n\\section{Дополнительные сведения}\n\n')
        files[0].write('\\textit{Было пропущено ' + str(skipped) + ' компонентов, так как они не были сочтены достаточно примечательными для отображения в отчёте. Полные сведения о компонентах доступны в формате SBoM-файла, который рекомендуется запросить у авторов отчёта.}')

    cve_batches = split(sbom.vulnerabilities, args.split) if args.split else [sbom.vulnerabilities]
    for batch, file in zip(cve_batches, files[1:]):
        file.write('\n\\section{Уязвимости}\n\n')
        for cve in batch:
            file.write(sbom_to_tex.encode_vuln(cve, sbom.components.get, args.shame))
            file.write(tex_utils.step())
            file.write(tex_utils.step())

    for f in files:
        f.write(report_brand.BOTTOM)
        f.close()
        if not args.split:
            break




