import json

json_string = 'C:\GitHub\StackOverflow'

try:
    parsed_json=json.loads(json_string)
    out=(json.dumps(parsed_json, indent=4,sort_keys=False))
    print(out)
except Exception as e:
    print(repr(e))