# Lessons

- When a source file has a size cap, check its opened handle and read no more than cap + 1 bytes. A prior pathname stat followed by `Path.read_bytes()` or `shutil.copyfile()` can race and consume an unbounded file. Add a regression that grows the file between stat and open.
