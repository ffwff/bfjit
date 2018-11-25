bfjit: bfjit.c
	$(CC) -o $@ $(CCFLAGS) -O3 -DOPTIMIZE $^

bfjit-64k: bfjit-64k.c
	$(CC) -o $@ -O3 -ffast-math -DOPTIMIZE $(CCFLAGS) $^

bfjit-64k-specexec: bfjit-64k-specexec.c
	$(CC) -o $@ -O3 -DOPTIMIZE $(CCFLAGS) $^

bfjit-64k-postpone: bfjit-64k-postpone.c
	$(CC) -o $@ -O3 -DOPTIMIZE $(CCFLAGS) $^

debug: bfjit.c
	$(CC) -g -o $@ -DDEBUG -DOPTIMIZE $(CCFLAGS) $^
	
debug-64k: bfjit-64k.c
	$(CC) -g -o $@ -DDEBUG -DOPTIMIZE $(CCFLAGS) $^
	
debug-64k-specexec: bfjit-64k-specexec.c
	$(CC) -g -o $@ -DDEBUG -DOPTIMIZE $(CCFLAGS) $^
	
debug-64k-postpone: bfjit-64k-postpone.c
	$(CC) -g -o $@ -DDEBUG -DOPTIMIZE $(CCFLAGS) $^
