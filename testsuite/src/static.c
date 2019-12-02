
#include <unistd.h>

char dsgjf()
{
	static char tourte = 'a';
	return(tourte++);
}

int main()
{
 char a;
 	while ((a=dsgjf()) < 'g')
		;
	return a - 'g';
}
