from dataclasses import dataclass, field


@dataclass
class ExampleNav:
    id: str
    title: str
    group: str
    difficulty: str
    endpoint: str

    def difficulty_badge_class(self) -> str:
        return {
            "Easy": "text-bg-success",
            "Medium": "text-bg-warning",
            "Hard": "text-bg-danger",
        }[self.difficulty]


@dataclass
class CategoryNav:
    id: str
    short_id: str
    title: str
    blueprint_name: str
    overview_endpoint: str
    examples: list = field(default_factory=list)
    seed_fn: object = None
    blurb: str = ""

    def grouped_examples(self):
        groups = {}
        order = []
        for example in self.examples:
            if example.group not in groups:
                groups[example.group] = []
                order.append(example.group)
            groups[example.group].append(example)
        return [(name, groups[name]) for name in order]


CATEGORIES: list = []
