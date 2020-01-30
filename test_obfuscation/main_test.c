
#include <stdio.h>

int comp(int a, int b)
{
	if (a < 5)
		return(1);
	return(a - b);
}


int main()
{
	static void *a = (void *)1;
	a = main;
	printf("\nSUs\n");
	printf("SUs%d\n", comp(5, 7));
	return(comp(4, 3));	
}
