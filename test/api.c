#include <stdlib.h>
#include "syslog.h"

int main(void)
{
	char *msg = getenv("MSG");

	if (!msg)
		return 1;

	syslog(LOG_ERR, msg);

	return 0;
}
