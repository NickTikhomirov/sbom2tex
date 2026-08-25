from dataclasses import dataclass
from collections import deque, defaultdict
from itertools import filterfalse, chain
import json

from .tex_utils import in_human

ALOT = 99999999999

SAFE_RESOLUTIONS = [
    "resolved",
    "resolved_with_pedigree",
    "not_affected",
    "false_positive",
]

VALID_GOST = ['yes', 'no', 'indirect']
DROP_OBOM = ["operating-system", "container"]
DROP_BUZZ = ["file", "cryptographic-asset"]


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
    solved_vulns: int = 0
    forced_interesting: bool = False
    important: bool = False

    @property
    def has_proper_src(self):
        return self.gost_provided_by or self.reference_type in ['vcs', 'source-distribution']

    @property
    def has_interesting_type(self):
        return self.type_ not in ['application', 'library', 'framework']

    @property
    def langs_as_list(self):
        return list(filter(bool, map(str.strip, self.langs.split(','))))

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
    src: str

    @property
    def severity_rank(self):
        return {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }.get(self.severity) or -1

    def __bool__(self):
        return all((self.score, self.method, self.severity))

    @staticmethod
    def Empty():
        return VulnerabilityGrade('0', '???', '', '???')

    @staticmethod
    def FromJSON(j: dict):
        return VulnerabilityGrade(
            score=str(j.get("score") or ''),
            method=j.get("method") or '',
            severity=j.get("severity") or '',
            src=j.get('source', dict()).get('name') or ''
        )

    def full_severity(self):
        if type(self) is not VulnerabilityGrade:
            '???'
        if not self.score or not self.score.strip('0.'):
            return self.severity
        return ' / '.join(filter(bool, (in_human(self.severity), self.score)))


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
        if len(self.grades) == 1:
            return self.grades[0]

        grades = list(self.grades)

        # gos bless stable sorts
        grades.sort(key=lambda x: x.src.lower() == 'nvd', reverse=True)
        grades.sort(key=lambda x: x.method or '', reverse=True)
        grades.sort(key=lambda x: x.method.lower().startswith('cvss'), reverse=True)
        grades.sort(key=bool, reverse=True)
        return grades[0]

    @property
    def main_id(self):
        for i in self.ids_:
            if i.startswith('CVE-'):
                return i
        for i in self.ids_:
            if i.startswith('BDU-'):
                return i
        return self.ids_[0]

    def get_some_ids(self, count: int):
        main_ = self.main_id
        all_ids = [main_] + list(set(self.ids_) - {main_})
        return all_ids[:count]

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
            desc=j.get('description') or j.get('detail') or '\n\n'.join(filter(bool, [i.get('url') for i in j.get('advisories', [])])) or '',
            grades=tuple(map(VulnerabilityGrade.FromJSON, j.get('ratings') or [])) or tuple([VulnerabilityGrade.Empty()]),
            components=tuple(str(a.get('ref')) or '' for a in (j.get("affects") or [])),
            own_bomref=j.get('bom-ref'),
            recommendation=j.get('recommendation') or j.get('workaround') or '',
            verdict_desc=analysis.get('detail') or '',
            verdict_stat=analysis.get('state') or '',
            ids_=tuple(Vulnerability.IdVectorFromJSON(j) or [j.get('id') or 'NO ID'])
        )

    @property
    def is_resolved(self):
        return bool(self.verdict_desc) and self.verdict_stat in SAFE_RESOLUTIONS


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
        self.back_edges: dict[str, list[str]] = defaultdict(list)
        self.signatures: dict[tuple, Component] = dict()
        self.aliases: dict[str, Component] = dict()
        self.make_signature = dedup_strategy
        self.ancestors: dict[int, list[Component]] = defaultdict(list)
        self.vulnerabilities: list[Vulnerability] = []
        self.timestamp = ''
        self.tools: list[Component] = []
        self.tool_signatures: dict[tuple, Component] = dict()

    def review_percent(self, predicate):
        vulnerable_bomrefs: list[tuple[Vulnerability, str]] = []
        for vuln in self.vulnerabilities:
            vulnerable_bomrefs.extend((vuln, c) for c in vuln.components)
        vulnerable_bomrefs = [i for i in vulnerable_bomrefs if predicate(self.get_or_alias(i[1]))]
        if not len(vulnerable_bomrefs):
            return float(100)
        return sum(1 for vul_and_cmp in vulnerable_bomrefs if vul_and_cmp[0].is_resolved) * 100.0 / len(vulnerable_bomrefs)

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
            return self.__count(lambda cmp: getter(cmp) not in VALID_GOST)
        return self.__count(lambda cmp: getter(cmp) == val)

    def count_containers(self):
        return self.__count(lambda cmp: cmp.type_ == "container") + int(self.root.type_ == 'container')

    def get_provided_by(self):
        result: dict[str, int] = defaultdict(int)
        for cmp in self.iter_components():
            if cmp.gost_provided_by:
                result[cmp.gost_provided_by] += 1
        return result

    def get_langs(self):
        result: dict[str, int] = defaultdict(int)
        for cmp in self.iter_components():
            for lang in cmp.langs_as_list:
                if not lang: continue
                result[lang] += 1
        return result

    def add_component(self, c: Component):
        signature = self.make_signature(c)
        if signature in self.signatures:
            our_component = self.signatures[signature]
            if c.bomref and c.bomref not in self.components:
                self.aliases[c.bomref] = our_component
            our_component.gost_provided_by = our_component.gost_provided_by or c.gost_provided_by
            our_component.gost_attack_surface = our_component.gost_attack_surface or c.gost_attack_surface
            our_component.gost_security_function = our_component.gost_security_function or c.gost_security_function
            our_component.langs = our_component.langs or c.langs
            our_component.purl = our_component.purl or c.purl
            return
        self.signatures[signature] = c

        if c.bomref:
            self.components[c.bomref] = c
        else:
            self.orphans.append(c)

    def add_tool(self, c: Component):
        signature = self.make_signature(c)
        if signature in self.tool_signatures:
            return
        self.tool_signatures[signature] = c
        self.tools.append(c)

    def add_edge(self, from_: str, to_: list[str]):
        check = self.get_or_alias
        if from_cmp := check(from_):
            from_ = from_cmp.bomref
        else: return
        valid_tos = list(filter(lambda x: check(x) is not None, to_))
        if valid_tos:
            self.edges[from_].extend(map(lambda x: check(x).bomref, valid_tos))

    def get_or_alias(self, ref: str):
        if cmp := self.components.get(ref):
            return cmp
        if cmp := self.aliases.get(ref):
            return cmp
        if ref == self.root.bomref:
            return self.root
        return None

    def add_vulnerability(self, vuln: Vulnerability):
        self.vulnerabilities.append(vuln)
        for ref in vuln.components:
            if cmp := self.get_or_alias(ref):
                cmp.vulns += 1
                if vuln.is_resolved:
                    cmp.solved_vulns += 1

    def __get_parentless_with_bomrefs(self):
        return list(map(self.components.get, set(self.components) - set(chain.from_iterable(self.edges.values()))))

    def get_actual_parentless(self):
        return self.__get_parentless_with_bomrefs() + self.orphans

    def build_backward_graph(self):
        self.back_edges = defaultdict(list)
        for from_, tos in self.edges.items():
            for to_ in tos:
                self.back_edges[to_].append(from_)

    def cleanup_edges(self):
        old_edges = self.edges
        self.edges = defaultdict(list)
        for from_, tos in old_edges.items():
            if not tos:
                continue
            self.edges[from_] = list(set(tos))

    def adopt(self):
        if self.root.bomref:
            self.add_edge(self.root.bomref, list(map(Component.get_bomref, self.__get_parentless_with_bomrefs())))

    def make_skips(self, types: list[str]):
        predicate = lambda x: x.type_ in types
        to_skip = filter(predicate, self.iter_components())
        resolutions: dict[str, list[str]] = defaultdict(list)
        to_skip_refs = set(map(lambda x: x.bomref, to_skip))

        def resolve(unwanted: str):
            back = self.back_edges.get
            ancestors = set(back(unwanted))
            result = set()
            visited = {unwanted}
            while ancestors:
                ancestors -= visited
                result |= (ancestors - to_skip_refs)
                visited |= ancestors
                ancestors = set(chain.from_iterable(filter(bool, map(back, ancestors))))
            resolutions[unwanted] = list(result)

        for skip_cmpref in to_skip_refs:
            if not (children := self.edges.get(skip_cmpref)):
                continue
            resolve(skip_cmpref)
            for child in children:
                if child not in self.components: continue  # somebody has cut some components from SBoM

                # forward:
                self.edges[child].extend(resolutions[skip_cmpref])

                # back:
                for skip in resolutions[skip_cmpref]:
                    self.edges[skip].append(child)

    def update_depths(self, ancestors_log_depth: int = 1):
        if not self.components:
            self.root.depth = 0
            for orphan in self.orphans:
                orphan.bomref = 1
            return

        to_visit: deque[tuple[Dull | Component, Component]] = deque([(Dull(), self.root)])
        orphans = self.get_actual_parentless()
        to_visit.extend((self.root, orphan) for orphan in orphans)
        enqueued = {self.root.bomref} | set(map(Component.get_bomref, orphans))
        while to_visit:
            parent_and_next_vertex = to_visit.popleft()
            parent, next_vertex = parent_and_next_vertex
            next_vertex.depth = min(next_vertex.depth, parent.depth + 1)

            children_refs = self.edges.get(next_vertex.bomref) or []
            children = list(filter(bool, map(self.components.get, filterfalse(enqueued.__contains__, children_refs))))
            to_visit.extend((next_vertex, child) for child in children)
            enqueued |= set(map(Component.get_bomref, children))

            ancestors_by_parent = self.ancestors[id(parent)]
            if 1 <= parent.depth <= ancestors_log_depth:
                ancestors_by_parent += [parent]
            already_known_ancestors = self.ancestors[id(next_vertex)]
            self.ancestors[id(next_vertex)] = identity_unique(already_known_ancestors, ancestors_by_parent)

    def sort_vulns(self):
        self.vulnerabilities.sort(key=lambda v: float(v.get_leading_grade().score or -1), reverse=True)
        self.vulnerabilities.sort(key=lambda v: v.get_leading_grade().severity_rank, reverse=True)

    def len_components(self):
        return len(self.components) + len(self.orphans)

    def len_vulnerabilities(self):
        return len(self.vulnerabilities)

    def __len__(self):
        return self.len_components() + self.len_vulnerabilities()

    def get_cmps_grouped_by_name(self):
        result: dict[str, list] = defaultdict(list)
        for cmp in self.iter_components():
            result[cmp.name].append(cmp)
        return result


def build_sbom_from_files(files, drop_types: list[str], dedup_strat=ComponentDedupPresets.default, skip_types: list[str] = None):
    sbom = SBoM(dedup_strat)
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
            tool_names = set()
            tools: dict | list = j.get('metadata', dict()).get('tools', dict())
            if type(tools) == dict:
                tools = tools.get('components', [])
            tools: list
            for cmp in map(Component.FromJSON, tools):
                if cmp.name in tool_names:
                    continue
                sbom.add_tool(cmp)
                tool_names.add(cmp.name)

    for src in files:
        with open(src, 'r', encoding='utf-8') as f:
            j = json.load(f)
            for raw_vuln in j.get('vulnerabilities') or []:
                sbom.add_vulnerability(Vulnerability.FromJSON(raw_vuln))

    sbom.adopt()
    sbom.cleanup_edges()
    sbom.build_backward_graph()
    if skip_types:
        sbom.make_skips(skip_types)
    sbom.cleanup_edges()
    sbom.update_depths()
    sbom.sort_vulns()
    return sbom


@dataclass
class ComponentEstimator:
    provided_by_is_not_interesting: bool
    no_gost: bool
    interesting_depth: int
    all_components: bool
    shame: bool
    counted: int = 0
    interesting: int = 0

    def __interesting_gost(self, value: str):
        if self.no_gost:
            return False
        if not self.shame:
            return value != 'no'
        return value in ['yes', 'indirect']

    def __call__(xelf, self: Component):
        xelf.counted += 1
        is_interesting = any((
            self.important,
            self.forced_interesting,
            self.gost_provided_by and not xelf.provided_by_is_not_interesting,
            xelf.__interesting_gost(self.gost_security_function),
            xelf.__interesting_gost(self.gost_attack_surface),
            self.vulns,
            self.has_interesting_type,
            xelf.shame and not self.has_proper_src
        )) or xelf.all_components or self.depth <= xelf.interesting_depth
        xelf.interesting += int(is_interesting)
        return is_interesting

