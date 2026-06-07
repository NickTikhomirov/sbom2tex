import itertools
from dataclasses import dataclass
from collections import deque, defaultdict
from itertools import filterfalse, chain
import json


ALOT = 99999999999

SAFE_RESOLUTIONS = [
    "resolved",
    "resolved_with_pedigree",
    "not_affected",
    "false_positive",
]

@dataclass
class Dull:
    type_: str = ''
    depth: int = -1


def identity_unique(*a: list[object]):
    result = []
    visited = set()
    for item in chain.from_iterable(a):
        if id(item) in visited:
            continue
        visited.add(id(item))
        result.append(item)
    return result


@dataclass
class Component:
    name: str
    version: str
    type_: str
    gost_security_function: str
    gost_attack_surface: str
    gost_provided_by: str
    langs: str
    purl: str
    bomref: str
    manufacturer: str
    reference: str
    reference_type: str
    depth: int = ALOT
    vulns: int = 0
    forced_interesting: bool = False

    @property
    def has_proper_src(self):
        return self.gost_provided_by or self.reference_type in ['vcs', 'source-distribution']

    @property
    def langs_as_list(self):
        return list(map(str.strip, self.langs.split(',')))

    def get_bomref(self):
        return self.bomref

    @staticmethod
    def Search(p: list[dict], key: str, keykey: str = 'name', valuekey: str = 'value', argsearch: bool=False):
        for i in p:
            if i.get(keykey) == key and i.get(valuekey):
                return i[valuekey] if not argsearch else i[keykey]


    @staticmethod
    def FromJSON(j: dict):
        props = j.get('properties') or []
        references = j.get('externalReferences') or []
        return Component(
            name=j['name'],
            version=j.get('version'),
            type_=j.get('type'),
            purl=j.get('purl'),
            bomref=j.get('bom-ref'),
            gost_attack_surface=Component.Search(props, 'GOST:attack_surface'),
            gost_security_function=Component.Search(props, 'GOST:security_function'),
            gost_provided_by=Component.Search(props, 'GOST:provided_by'),
            langs=Component.Search(props, 'GOST:source_langs') or '',
            manufacturer=j.get('manufacturer', dict()).get('name') or '',
            reference=Component.Search(references, 'vcs', 'type', 'url') or Component.Search(references, 'source-distribution', 'type', 'url'),
            reference_type=Component.Search(references, 'vcs', 'type', 'url', True) or Component.Search(references, 'source-distribution', 'type', 'url', True),
        )


@dataclass
class VulnerabilityGrade:
    score: str
    method: str
    severity: str

    @staticmethod
    def Empty():
        return VulnerabilityGrade('5', '???', '???')

    @staticmethod
    def FromJSON(j: dict):
        return VulnerabilityGrade(
            score=str(j.get("score")) or '',
            method=j.get("method") or '',
            severity=j.get("severity") or '',
        )



@dataclass
class Vulnerability:
    ids_: tuple[str]
    cwes: tuple[str]
    desc: str
    grades: tuple[VulnerabilityGrade]
    verdict_desc: str
    verdict_stat: str
    recommendation: str
    components: tuple[str]
    own_bomref: str | None

    def get_leading_grade(self) -> VulnerabilityGrade:
        return self.grades[-1]

    @property
    def main_id(self):
        for i in self.ids_:
            if i.startswith('CVE-'):
                return i
        for i in self.ids_:
            if i.startswith('BDU-'):
                return i
        return self.ids_[0]

    @staticmethod
    def IdVectorFromJSON(j: dict):
        if not (refs := j.get('references')):
            return []
        return [ref['id'] for ref in refs if ref.get('id')]

    @staticmethod
    def FromJSON(j: dict):
        analysis = j.get('analysis', dict())
        return Vulnerability(
            cwes=j.get('cwes') or [],
            desc=j.get('description') or j.get('detail') or '',
            grades=tuple(map(VulnerabilityGrade.FromJSON, j.get('ratings') or [])) or tuple([VulnerabilityGrade.Empty()]),
            components=tuple(str(a.get('ref')) or '' for a in (j.get("affects") or [])),
            own_bomref=j.get('bom-ref'),
            recommendation=j.get('recommendation') or j.get('workaround') or '',
            verdict_desc=analysis.get('detail') or '',
            verdict_stat=analysis.get('state') or '',
            ids_=tuple(Vulnerability.IdVectorFromJSON(j) or [j.get('id') or 'NO ID'])
        )


class ComponentDedupPresets:
    def __init__(self):
        self.ctr = 0

    @staticmethod
    def default(c: Component):
        return c.name, c.version


class SBoM:
    def __init__(self, dedup_strategy):
        self.root: Component | None = None
        self.components: dict[str, Component]= dict()
        self.orphans: list[Component] = []
        self.edges: dict[str, list[str]] = defaultdict(list)
        self.vulnerabilities = []
        self.signatures = set()
        self.make_signature = dedup_strategy
        self.ancestors: dict[int, list[Component]] = defaultdict(list)
        self.vulnerabilities: list[Vulnerability] = []
        self.timestamp = ''

    def iter_components(self):
        yield from self.orphans
        yield from self.components.values()

    def all_languages(self):
        return list(set(chain.from_iterable(map(lambda x: x.langs_as_list, self.iter_components()))))

    def __count(self, predicate):
        return sum(1 for cmp in self.iter_components() if predicate(cmp))

    def count_property_by_value(self, prop: str, val: str):
        getter = (lambda c: c.gost_attack_surface) if prop == 'as' else (lambda c: c.gost_security_function)
        if val == 'TODO':
            return self.__count(lambda cmp: getter(cmp) not in ['yes', 'no', 'indirect'])
        return self.__count(lambda cmp: getter(cmp) == val)

    def count_containers(self):
        return self.__count(lambda cmp: cmp.type_ == "container")

    def get_provided_by(self):
        result: dict[str, int] = defaultdict(int)
        for cmp in self.iter_components():
            if cmp.gost_provided_by:
                result[cmp.gost_provided_by] += 1
        return result

    def add_component(self, c: Component):
        signature = self.make_signature(c)
        if signature in self.signatures:
            return
        self.signatures.add(signature)

        if c.bomref:
            self.components[c.bomref] = c
        else:
            self.orphans.append(c)

    def add_edge(self, from_: str, to_: list[str]):
        self.edges[from_].extend(to_)

    def add_vulnerability(self, vuln: Vulnerability):
        self.vulnerabilities.append(vuln)
        for ref in vuln.components:
            if self.components.get(ref):
                self.components[ref].vulns += 1

    def get_actual_parentless(self):
        return list(map(self.components.get, set(self.components) - set(chain.from_iterable(self.edges.values())))) + self.orphans

    def update_depths(self, ancestors_log_depth: int = 1):
        if not self.components:
            self.root.depth = 0
            for orphan in self.orphans:
                orphan.bomref = 1
            return

        to_visit: deque[tuple[Dull | Component, Component]] = deque([(Dull(), self.root)])
        orphans = self.get_actual_parentless()
        to_visit.extend((self.root, orphan) for orphan in orphans)
        visited = set()
        while to_visit:
            parent_and_next_vertex = to_visit.popleft()
            parent, next_vertex = parent_and_next_vertex
            #next_depth = parent.depth + 1 - int(ignore_obom and parent.type_ in DROP_OBOM)
            next_vertex.depth = min(next_vertex.depth, parent.depth + 1)
            if next_vertex.bomref:
                visited.add(next_vertex.bomref)

            children_refs = self.edges.get(next_vertex.bomref) or []
            children = filter(bool, map(self.components.get, filterfalse(visited.__contains__, children_refs)))
            to_visit.extend((next_vertex, child) for child in children)

            ancestors_by_parent = self.ancestors[id(parent)]
            if 1 <= parent.depth <= ancestors_log_depth:
                ancestors_by_parent += [parent]
            already_known_ancestors = self.ancestors[id(next_vertex)]
            self.ancestors[id(next_vertex)] = identity_unique(already_known_ancestors, ancestors_by_parent)

    def sort_vulns(self):
        self.vulnerabilities.sort(key=lambda v: float(v.get_leading_grade().score), reverse=True)

    def len_components(self):
        return len(self.components) + len(self.orphans)

    def len_vulnerabilities(self):
        return len(self.vulnerabilities)

    def __len__(self):
        return self.len_components() + self.len_vulnerabilities()


def build_sbom_from_files(files, drop_types: list[str]):
    sbom = SBoM(ComponentDedupPresets.default)
    for src in files:
        with open(src, 'r', encoding='utf-8') as f:
            j = json.load(f)
            if not sbom.timestamp:
                sbom.timestamp = str(j.get('metadata', dict()).get('timestamp', ''))
            if not sbom.root:
                sbom.root = Component.FromJSON(j['metadata']['component'])
            for cmp in map(Component.FromJSON, j.get('components') or []):
                if cmp.type_ in drop_types:
                    continue
                sbom.add_component(cmp)
            for edge in j.get('dependencies') or []:
                if edge.get('dependsOn'):
                    sbom.add_edge(edge['ref'], edge['dependsOn'])

        for src in files:
            with open(src, 'r', encoding='utf-8') as f:
                j = json.load(f)
                for raw_vuln in j.get('vulnerabilities') or []:
                    sbom.add_vulnerability(Vulnerability.FromJSON(raw_vuln))

        sbom.update_depths()
        sbom.sort_vulns()
        return sbom


@dataclass
class ComponentEstimator:
    provided_by_is_not_interesting: bool

    def __call__(xelf, self):
        return any((
            self.forced_interesting,
            self.gost_provided_by and not xelf.provided_by_is_not_interesting,
            self.gost_security_function != 'no',
            self.gost_attack_surface != 'no',
            self.vulns,
            self.type_ not in ['application', 'library', 'framework'],
            not self.has_proper_src
        ))

