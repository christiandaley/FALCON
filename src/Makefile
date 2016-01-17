CFLAGS = -Ofast -DNDEBUG

all: test benchmark

test: test.o FALCON_ref.o
	gcc $(CFLAGS) test.o FALCON_ref.o -o test

benchmark: benchmark.o rijndael-alg-fst.o FALCON_opt.o
	gcc $(CFLAGS) benchmark.o rijndael-alg-fst.o FALCON_opt.o -o benchmark

clean:
	rm *~ *.o test benchmark