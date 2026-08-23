# this is debug script for parsing CWE hierarchy to dicts
# used for codegen, not for actual work

import xml.etree.ElementTree as ET
from collections import defaultdict

def is_related(item):
    name: str = item.tag
    return name.split('}')[1] == 'Related_Weaknesses'

def is_member(item):
    name: str = item.tag
    return name.split('}')[1] == 'Has_Member'


def to_list(weakness):
    id_ = weakness.get('ID')
    try:
        related_weaknesses = list(list(k for k in weakness if is_related(k))[0])
        return id_, [rel.get('CWE_ID') for rel in related_weaknesses if rel.get('Nature') == "ChildOf"]
    except IndexError:
        return id_, []


tree = ET.parse('cwec_v4.20.xml')
root = tree.getroot()
namespace = ''
if root.tag.startswith('{'):
    namespace = root.tag.split('}')[0] + '}'

all_edges = defaultdict(set)

all_reverse_edges = [to_list(w) for w in root.findall(f'.//{namespace}Weakness')]
for child, parents in all_reverse_edges:
    for parent in parents:
        all_edges[parent].add(child)

for cat in root.findall(f'.//{namespace}Category'):
    for child in cat:
        if not child.tag.endswith('Relationships'):
            continue
        all_edges[cat.get('ID')].update(map(lambda x: x.get('CWE_ID'), filter(is_member, child)))

for k,v in all_edges.items():
    print(f'{k}: {list(v)},')

