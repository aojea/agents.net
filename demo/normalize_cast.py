#!/usr/bin/env python3
import json
import sys

filename = sys.argv[1] if len(sys.argv) > 1 else "demo/terminal-demo.cast"

with open(filename, "r") as f:
    lines = f.readlines()

if not lines:
    sys.exit(0)

header = json.loads(lines[0])
header["idle_time_limit"] = 5.0

out = [json.dumps(header) + "\n"]
current_time = 0.0
last_orig_time = 0.0

for line in lines[1:]:
    line_str = line.strip()
    if not line_str:
        continue
    try:
        item = json.loads(line_str)
        orig_t = item[0]
        dt = orig_t - last_orig_time
        if dt < 0:
            dt = 0.1
        last_orig_time = orig_t

        # Preserve step pauses (up to 6.0s), capping only excessive timeouts (> 6.0s) down to 4.5s
        if dt > 6.0:
            dt = 4.5

        current_time += dt
        item[0] = round(current_time, 6)
        out.append(json.dumps(item) + "\n")
    except Exception as e:
        out.append(line)

with open(filename, "w") as f:
    f.writelines(out)

print(f"Normalized {len(out)} frames in {filename}, total duration: {current_time:.2f}s")
