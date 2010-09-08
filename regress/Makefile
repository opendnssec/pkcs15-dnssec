# $Id$

VERSION=	0.1

DISTNAME=	pkcs15-dnssec-${VERSION}
TARGET=		pkcs15-dnssec
OBJS=		pkcs15-dnssec.o pkcs15-util.o dns-util.o base64.o

INCLUDES=	-I/usr/local/opensc/include
LIBRARIES=	-L/usr/local/opensc/lib

CFLAGS=		-g -Wall $(INCLUDES)
LDFLAGS=	$(LIBRARIES)
LDLIBS=		-lopensc -lcrypto


all: $(TARGET)

$(TARGET): $(OBJS)

dist:
	cvs export -d ${DISTNAME} -r HEAD `cat CVS/Repository`
	tar cvzf ${DISTNAME}.tar.gz ${DISTNAME}
	rm -fr ${DISTNAME}

clean:
	rm -f *.o $(TARGET)

cleandir: clean
	rm -f *.tar.gz
