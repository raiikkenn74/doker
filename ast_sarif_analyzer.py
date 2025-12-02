import argparse
import ast
import json

class SARIFReporter:
    def __init__(self, tool_name="Analyzeer"):
        self.sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": tool_name}},
                "results": []
            }]
        }

    def add(self, rule_id, message, line):
        self.sarif['runs'][0]['results'].append({
            "ruleId": rule_id,
            "message": {"text": message},
            "locations": [{"physicalLocation": {"region": {"startLine": line}}}]
        })

    def save(self, path):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.sarif, f, indent=2, ensure_ascii=False)

class ASTAnalyzer(ast.NodeVisitor):
    def __init__(self, reporter):
        self.reporter = reporter
        self.prev_node = None

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id == 'eval':
            self.reporter.add('eval-call', 'Использование eval()', node.lineno)
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str) and len(node.value) >= 6:
            self.reporter.add('user-secret', 'Обнаружена потенциальная утечка секрета', node.lineno)

    def visit_Assign(self, node):
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if targets and isinstance(self.prev_node, ast.Assign):
            prev_t = [t.id for t in self.prev_node.targets if isinstance(t, ast.Name)]
            if prev_t and prev_t[0] == targets[0]:
                self.reporter.add(
                    'consec-assign',
                    f"Два подряд присваивания переменной '{targets[0]}'", node.lineno
                )
        self.prev_node = node
        self.generic_visit(node)

    def visit_Expr(self, node):
        if isinstance(node.value, (ast.Constant,)) and self.prev_node:
            if isinstance(self.prev_node, ast.Expr) and ast.dump(self.prev_node.value) == ast.dump(node.value):
                self.reporter.add('duplicate-line', 'Дублирующаяся строка', node.lineno)
        self.prev_node = node
        self.generic_visit(node)

def dump_ast_examples(examples):
    for title, code in examples.items():
        tree = ast.parse(code)
        print(f"=== AST для {title} ===")
        print(ast.dump(tree, indent=2))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AST-based static analysis with SARIF output')
    parser.add_argument('file', help='Анализируемый Python-файл')
    parser.add_argument('--output', '-o', default='ast_results.sarif.json', help='Файл SARIF-отчёта')
    args = parser.parse_args()

    reporter = SARIFReporter()
    analyzer = ASTAnalyzer(reporter)

    with open(args.file, encoding='utf-8') as f:
        src = f.read()
    tree = ast.parse(src)
    analyzer.visit(tree)
    reporter.save(args.output)
    print(f"AST SARIF отчёт сохранён в {args.output}")

    examples = {
        "Eval-пример": 'x = eval("2+2")',
        "Секрет-пример": 'token = "P@ssw0rd"',
        "Дублирование": '''print("Hi")\nprint("Hi")''',
        "Присваивание": '''x = 1\nx = 2'''
    }
    dump_ast_examples(examples)

