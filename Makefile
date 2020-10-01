CFLAGS := -g -Wall
LDFLAFS := -lpcap
CC := gcc
RM := rm

TARGET := raw_sniffer sniffer arp_sniffer

.PHONY: clean

all: $(TARGET)

.SECONDEXPANSION:
$(TARGET): $$@.o
	@echo [INFO] Creating Binary Executable [$@]
	@$(CC) -o $@ $^ $(LDFLAFS)
	@rm -vf $<

%.o: %.c
	@echo [CC] $<
	@$(CC) $(CFLAGS) -o $@ -c $<

clean:
	@rm -vf $(TARGET)