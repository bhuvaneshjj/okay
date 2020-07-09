########################################################################
# This is a utility to deliver an Authenticated Login Token to a       #
# Target system, allowing for public-key authenticated SSH logins.     #
########################################################################


CC  = $(CROSS)gcc
CPP = $(CROSS)g++
LD  = $(CROSS)g++

OBJECTS = main.o

TARGET = auth_login_token_delivery

#
# main target
#
all: $(TARGET)

SRCS := main.c


OBJS := $(SRCS:.c=.o)

%.o: %.c Makefile
	$(CPP) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS) Makefile
	$(LD) $(OBJS) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(OBJS) *~ $(TARGET)
