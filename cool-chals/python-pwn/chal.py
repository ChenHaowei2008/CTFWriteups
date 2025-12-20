from my_arrays import *
import base64, ast

class SecurityError(Exception):
    pass

class SecurityVisitor(ast.NodeVisitor):
    FORBIDDEN_BUILTINS = {
        'getattr', 'setattr', 'delattr', 'hasattr',
        'eval', 'exec', '__import__', 'open'
    }

    def visit_Attribute(self, node):
        """Blocks direct attribute access like 'obj.attr'."""
        try:
            forbidden_code = ast.unparse(node)
        except AttributeError:
            forbidden_code = f".{node.attr}"
        
        raise SecurityError(
            f"Attribute access is forbidden. "
            f"Found '{forbidden_code}' on line {node.lineno}."
        )

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in self.FORBIDDEN_BUILTINS:
            raise SecurityError(
                f"Calling the built-in function '{node.func.id}' is forbidden."
            )
        self.generic_visit(node)



def to_little_endian_bytes(n):
    n &= (1 << 64) - 1
    return bytes(((n >> (8 * i)) & 0xFF) for i in range(8))
def from_little_endian_bytes(b):
    assert len(b) == 8
    n = 0
    for i in range(8):
        n |= (b[i] & 0xFF) << (8 * i)
    return n
def system_append(l, d):
    l.append(d)

def safe_exec_with_printer(code_string: str):
    try:
        tree = ast.parse(code_string)
        visitor = SecurityVisitor()
        visitor.visit(tree)
    except SyntaxError as e:
        print(f"Error: Invalid Python syntax. {e}")
        return
    except SecurityError as e:
        print(f"Execution blocked! {e}")
        return
    except Exception as e:
        print(f"An unexpected error occurred during security analysis: {e}")
        return
    allowed_globals = {
        '__builtins__': {},
        'range': range,
        'id': id,
        'list': list,
        'set': set,
        'bytearray': bytearray,
        'str': str,
        'int': int,
        'len': len,
        'input': input,
        'print': print,
        'hex': hex,
        'system_append': system_append,
        'bytes': bytes,
        'myexit': myexit,
        'my_append': my_append,
        'my_set': my_set,
        'exit': exit,
        'to_little_endian_bytes': to_little_endian_bytes,
        'from_little_endian_bytes': from_little_endian_bytes,
        'True': True,
        'False': False,
        'None': None,
    }

    local_namespace = {}
    try:
        exec(code_string, allowed_globals, local_namespace)
    except Exception as e:
        print(e)
        
b64 = input("Please enter base64 script: ").encode("ascii")
safe_exec_with_printer(base64.b64decode(b64).decode("charmap"))