#include <string.h>
int  match(int       a, int b)

{

	return a==b;

}
int match1(char*a, char*b)
{
	strcpy(a,b);
	return 1;
}