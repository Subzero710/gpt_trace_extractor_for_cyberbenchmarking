from pathlib import Path
for p in Path('evidence').rglob('*'):
 if p.is_file():print(p,p.stat().st_size)
