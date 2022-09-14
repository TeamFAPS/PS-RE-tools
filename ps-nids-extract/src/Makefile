TARGET = ps-nids-extract
OBJS = main.o
LIBS =
CFLAGS = -s -static -Os -Wall -Wextra -std=c99
all: $(TARGET)

$(TARGET): $(OBJS)
	@echo "Creating binary $(TARGET)"
	$(CXX) $(CFLAGS) $(OBJS) -o $@ $(LIBS)

clean:
	@echo "Removing all the .o files"
	@$(RM) $(OBJS)

mrproper: clean
	@echo "Removing binary"
	@$(RM) $(TARGET)

install: all
	@cp $(TARGET) ../bin