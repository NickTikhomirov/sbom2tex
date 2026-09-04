import itertools
import json
import sys

#if 0
from src import bdu_mappings
#endif
#include "./src/bdu_mappings.py"

PROPERTIES = 'properties'



def ensure_properties(cve: dict):
    if PROPERTIES not in cve:
        cve[PROPERTIES] = []


def extract_property_by_name(cve: dict, property_name: str):
    is_target_property = lambda x: x.get('name') == property_name
    result = [prop for prop in cve[PROPERTIES] if is_target_property(prop)]
    cve[PROPERTIES] = [prop for prop in cve[PROPERTIES] if not is_target_property(prop)]
    return result


def check_property_value_is_valid(property_dict: dict):
    property_value = property_dict['value']
    bdus = set(map(str.strip, property_value.split(',')))
    valid_values = set(map(str, bdu_mappings.BDU_MAPPINGS))
    return bdus & valid_values == bdus


def encrich(cve: dict, property_name: str, strategy: str, is_comma_separated_: bool):
    ensure_properties(cve)
    cwes = cve.get('cwes') or []
    present_bdus_unchecked = extract_property_by_name(cve, property_name)
    if strategy in ['skip', 'ignore'] and present_bdus_unchecked:
        cve[PROPERTIES].extend(present_bdus_unchecked)
        return

    bdus = list(map(str, bdu_mappings.get_mapping(bdu_mappings.BDU_MAPPINGS, *cwes)))
    if strategy == 'append':
        bdus += list(
            map(str.strip,
                itertools.chain.from_iterable(
                    map(lambda x: x.split(','),
                        map(lambda x: x['value'],
                            filter(check_property_value_is_valid,
                                   present_bdus_unchecked
                                   ))))))
    if not bdus:
        return
    bdus = list(sorted(set(bdus)))
    if is_comma_separated_:
        property_value = ', '.join(bdus)
        cve[PROPERTIES].append({"name": property_name, "value": property_value})
    else:
        for bdu in bdus:
            cve[PROPERTIES].append({"name": property_name, "value": bdu})


if len(sys.argv) < 3:
    print('The script adds for CVEs in SBoM additional info on relation to BDU FSTEC WEB TOP-5')
    print('  More on: https://bdu.fstec.ru/webvulns (Russian Root Certificate required)')
    print('')
    print('Usage:')
    print('  $ bdu_top5_enricher.py ./input.json ./output.json [-c]')
    print()
    print('Use "-c" at third position in order to make values comma-separate')
    exit(1)

input_file = sys.argv[1]
output_file = sys.argv[2]
flags = sys.argv[3:]
is_comma_separated = '-c' in flags

with open(input_file, 'r', encoding='utf-8') as f:
    sbom = json.load(f)

for vuln in sbom.get('vulnerabilities') or []:
    encrich(vuln, "GOST:BDU_WEB", 'overwrite', True)

with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(sbom, f, indent=4, ensure_ascii=False)


