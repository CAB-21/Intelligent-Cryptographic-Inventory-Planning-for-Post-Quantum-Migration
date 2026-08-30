import os
import sys
import json
from tree_sitter import Language, Parser
import tree_sitter_c as tsc
import tree_sitter_java as tsj

# Prevent recursion limit crashes on complex macro ASTs
sys.setrecursionlimit(50000)

C_LANG = Language(tsc.language())
JAVA_LANG = Language(tsj.language())

c_parser = Parser(C_LANG)
java_parser = Parser(JAVA_LANG)

def inspect_c_file_iterative(root_node, source_code, file_path):
    findings = []
    stack = [root_node]

    while stack:
        node = stack.pop()

        # 1. Detect Fixed Array Allocations (C/C++)
        if node.type == 'array_declarator':
            size_node = node.child_by_field_name('size')
            var_name_node = node.child_by_field_name('declarator')
            if size_node and size_node.type == 'number_literal':
                try:
                    allocated_bytes = int(source_code[size_node.start_byte:size_node.end_byte].decode('utf-8'))
                    var_name = source_code[var_name_node.start_byte:var_name_node.end_byte].decode('utf-8') if var_name_node else "anonymous"
                    findings.append({
                        "layer": "Provider_Layer (C/C++)",
                        "file": file_path,
                        "line": node.start_point[0] + 1,
                        "variable_name": var_name,
                        "allocated_bytes": allocated_bytes,
                        "ast_type": "Fixed_Array_Buffer",
                        "language": "C/C++"
                    })
                except ValueError:
                    pass

        # 2. Detect PKCS#11 Data Structure Types
        elif node.type == 'type_identifier':
            type_name = source_code[node.start_byte:node.end_byte].decode('utf-8')
            if type_name in ['CK_MECHANISM', 'CK_ATTRIBUTE', 'CK_SESSION_HANDLE', 'CK_OBJECT_HANDLE']:
                findings.append({
                    "layer": "Provider_Layer (C/C++)",
                    "file": file_path,
                    "line": node.start_point[0] + 1,
                    "pkcs11_structure": type_name,
                    "ast_type": "PKCS11_Type_Declaration",
                    "language": "C/C++"
                })

        # 3. Detect PKCS#11 Constant Mechanism Usages (e.g., CKM_RSA_PKCS, CKM_ECDSA)
        elif node.type == 'identifier':
            ident_name = source_code[node.start_byte:node.end_byte].decode('utf-8')
            if ident_name.startswith("CKM_") or ident_name.startswith("CKA_"):
                findings.append({
                    "layer": "Provider_Layer (C/C++)",
                    "file": file_path,
                    "line": node.start_point[0] + 1,
                    "pkcs11_constant": ident_name,
                    "ast_type": "PKCS11_Mechanism_Reference",
                    "language": "C/C++"
                })

        # Push children onto iterative stack
        stack.extend(node.children)

    return findings

def inspect_java_file_iterative(root_node, source_code, file_path):
    findings = []
    stack = [root_node]

    while stack:
        node = stack.pop()

        # 1. Detect Dynamic JCA / JCE Provider Invocations
        if node.type == 'method_invocation':
            name_node = node.child_by_field_name('name')
            args_node = node.child_by_field_name('arguments')
            
            if name_node and source_code[name_node.start_byte:name_node.end_byte].decode('utf-8') == 'getInstance' and args_node:
                for child in args_node.children:
                    if child.type == 'string_literal':
                        algo_str = source_code[child.start_byte:child.end_byte].decode('utf-8').replace('"', '')
                        findings.append({
                            "layer": "Gateway_Layer (Java)",
                            "file": file_path,
                            "line": node.start_point[0] + 1,
                            "algorithm_call": algo_str,
                            "ast_type": "JCA_Provider_Invocation",
                            "language": "Java"
                        })

        # 2. Detect Dynamic Heap Byte Array Allocations
        elif node.type == 'array_creation_expression':
            for child in node.children:
                if child.type == 'dimensions_expr':
                    for dim_child in child.children:
                        if dim_child.type == 'decimal_integer_literal':
                            try:
                                allocated_bytes = int(source_code[dim_child.start_byte:dim_child.end_byte].decode('utf-8'))
                                findings.append({
                                    "layer": "Gateway_Layer (Java)",
                                    "file": file_path,
                                    "line": node.start_point[0] + 1,
                                    "allocated_bytes": allocated_bytes,
                                    "ast_type": "Java_ByteArray_Allocation",
                                    "language": "Java"
                                })
                            except ValueError:
                                pass

        # Push children onto iterative stack
        stack.extend(node.children)

    return findings

def scan_full_codebases():
    all_findings = []
    
    # 1. Scan SoftHSMv2 C++ Source Tree
    softhsm_src = os.path.expanduser("~/cryptograph_pqc/SoftHSMv2/src")
    if os.path.exists(softhsm_src):
        print(f"[*] Scanning SoftHSMv2 C++ ASTs across: {softhsm_src}")
        for root, _, files in os.walk(softhsm_src):
            for file in files:
                if file.endswith(('.cpp', '.h', '.c', '.hpp')):
                    p = os.path.join(root, file)
                    try:
                        with open(p, "rb") as f:
                            code = f.read()
                        tree = c_parser.parse(code)
                        all_findings.extend(inspect_c_file_iterative(tree.root_node, code, p))
                    except Exception as e:
                        print(f"[-] Skipping unparseable file {file}: {e}")
    else:
        print(f"[!] SoftHSMv2 source path not found at {softhsm_src}")

    # 2. Scan jPOS Java Source Tree
    jpos_src = os.path.expanduser("~/cryptograph_pqc/jPOS/jpos/src/main/java")
    if os.path.exists(jpos_src):
        print(f"[*] Scanning jPOS Java ASTs across: {jpos_src}")
        for root, _, files in os.walk(jpos_src):
            for file in files:
                if file.endswith('.java'):
                    p = os.path.join(root, file)
                    try:
                        with open(p, "rb") as f:
                            code = f.read()
                        tree = java_parser.parse(code)
                        all_findings.extend(inspect_java_file_iterative(tree.root_node, code, p))
                    except Exception as e:
                        print(f"[-] Skipping unparseable file {file}: {e}")
    else:
        print(f"[!] jPOS source path not found at {jpos_src}")

    output_file = "production_sast_cbom_evidence.json"
    with open(output_file, "w") as out:
        json.dump(all_findings, out, indent=2)

    print(f"\n[+] AST Extraction Complete: Discovered {len(all_findings)} authentic cryptographic declarations.")
    print(f"[+] Output saved to: {output_file}")

if __name__ == "__main__":
    scan_full_codebases()
