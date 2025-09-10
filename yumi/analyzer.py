import esprima

def find_api_endpoints(js_content):
    endpoints = set()
    try:
        tree = esprima.parseScript(js_content, {'tolerant': True, 'loc': True})
        
        for node in tree.body:
            if node.type == 'ExpressionStatement' and node.expression.type == 'CallExpression':
                callee = node.expression.callee
                
              
                if callee.type == 'Identifier' and callee.name == 'fetch':
                    if node.expression.arguments and node.expression.arguments[0].type == 'Literal':
                        endpoints.add(node.expression.arguments[0].value)
                        
               
                elif callee.type == 'MemberExpression' and callee.property.name in ('ajax', 'get', 'post', 'put', 'delete'):
                    if node.expression.arguments:
                        first_arg = node.expression.arguments[0]
                        if first_arg.type == 'ObjectExpression': 
                            for prop in first_arg.properties:
                                if hasattr(prop.key, 'name') and prop.key.name == 'url':
                                    endpoints.add(prop.value.value)
                        elif first_arg.type == 'Literal': 
                            endpoints.add(first_arg.value)
    except Exception:
        pass
    return list(endpoints)

def analyze_js(url, content):
    """The main analysis function that runs all AST-based checks."""
    findings = []
    endpoints = find_api_endpoints(content)
    if endpoints:
        for endpoint in endpoints:
            if isinstance(endpoint, str) and (endpoint.startswith('/') or 'api' in endpoint):
                findings.append({"url": url, "type": "API Endpoint", "match": endpoint})
    return findings
