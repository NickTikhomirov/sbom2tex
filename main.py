import argparse
from pathlib import Path

from src import report_brand
from src import tex_utils
from src import sbom_lib


DROP_OBOM = ["operating-system", "container"]
DROP_BUZZ = ["file", "cryptographic-asset"]


def argparse_init():
    parser = argparse.ArgumentParser(description='DependencyTrack PDF Report Client')
    parser.add_argument('-i', '--input', type=Path, action='append', help='DependencyTrack Inventory or VDR')
    parser.add_argument('-o', '--output', default='.', type=Path, help='Directory to store result')
    parser.add_argument('-n', '--name', type=str, default='', help='Project main name (for title)')
    parser.add_argument('--split', type=int, default=0, help='Split threshold (0 for no split, >19 otherwise)')

    parser.add_argument('--introspect-depth', type=int, default=0, help='For ')
    #parser.add_argument('--ignore-obom-depth', action='store_true', help='If set, depth will preserve same for components with types:' + ', '.join(DROP_OBOM))

    parser.add_argument('--no-cve', action='store_true', help='Remove CVE section')
    parser.add_argument('--no-gost', action='store_true', help='Remove all GOST properties')
    parser.add_argument('--no-obom', action='store_true', help='Drop all components with types: ' + ', '.join(DROP_OBOM))
    parser.add_argument('--no-buzz', action='store_true', help='Drop all components with types: ' + ', '.join(DROP_BUZZ))

    parser.add_argument('-O', '--opinionated', action='store_true', help='Use author\'s favourite preset')

    add_to_title_help = [
        '"-t t" is reserved for SBoM timestamp'
        '"-t d" is reserved for current date (no time)'
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
        #args.ignore_obom_depth = True

    drop_types = (DROP_OBOM if args.no_obom else []) + (DROP_BUZZ if args.no_buzz else [])
    sbom = sbom_lib.build_sbom_from_files(args.input, drop_types)

    out_dir: Path = args.output
    component_filename = out_dir.joinpath(f'report_components')
    files = []
    filenames = []
    quick_open = lambda x: open(x, 'w', encoding='utf-8')
    common_part_builder = report_brand.make_common_builder(sbom)

    if len(sbom) <= args.split * 1.5 or not args.split:  # single file
        filenames += [str(out_dir.joinpath(f'report'))]
        files += [quick_open(fname + '.tex') for fname in filenames]
        files[0].write(report_brand.TOP)
        report_brand.add_title_page(files[0], args.name or 'Отчёт об уязвимостях', [report_brand.decode_line(l, sbom.timestamp) for l in args.add_to_title], tex_utils.protect)
        common = common_part_builder(tex_utils.protect('Это общий (цельный, без разделения на части) отчёт по проекту, содержащий сведения о проекте ' + args.name + ' -- его компонентах и уязвимостях.'))
        files[0].write(common)

    elif len(sbom.vulnerabilities) <= args.split:        # two files: components + cves
        cve_filename = out_dir.joinpath(f'report_cve')
        filenames += [component_filename, cve_filename]
        files += [quick_open(fname + '.tex') for fname in filenames]
        report_brand.add_title_page(files[0], args.name or 'Отчёт о компонентах', [report_brand.decode_line(l, sbom.timestamp) for l in args.add_to_title], tex_utils.protect)
        report_brand.add_title_page(files[1], args.name or 'Отчёт об уязвимостях', [report_brand.decode_line(l, sbom.timestamp) for l in args.add_to_title], tex_utils.protect)
        common = common_part_builder(tex_utils.protect('Это отчёт о компонентах проекта ' + args.name + '. Сведения об уязвимостях приведены в отдельном отчёте. Разделение отчётов было осуществлено для повышения читаемости.'))
        files[0].write(common)
        common = common_part_builder(tex_utils.protect('Это отчёт об уязвимостях проекта ' + args.name + '. Сведения о компонентах приведены в отдельном отчёте. Разделение отчётов было осуществлено для повышения читаемости.'))
        files[1].write(common)

    else:                                                # a lot of files
        report_count = (len(sbom.vulnerabilities) * 1.0 / args.split).__ceil__() if args.split else 1
        cve_filename = lambda i: out_dir.joinpath(f'report_cve_{i}')
        filenames += [component_filename] + [cve_filename(i+1) for i in range(report_count)]
        files += [quick_open(fname + '.tex') for fname in filenames]
        report_brand.add_title_page(files[0], args.name or 'Отчёт о компонентах', [report_brand.decode_line(l, sbom.timestamp) for l in args.add_to_title], tex_utils.protect)
        for file in files[1:]:
            report_brand.add_title_page(file, args.name or 'Отчёт об уязвимостях', [report_brand.decode_line(l, sbom.timestamp) for l in args.add_to_title], tex_utils.protect)

    for f in files:
        f.write(report_brand.BOTTOM)
        f.close()




