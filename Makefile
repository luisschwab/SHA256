build:
	gcc -o main main.c sha256.c
	@echo -n "\n"

run:
	make build
	@echo -n "\n"
	./main

clean:
	rm main sha256 sha256.o