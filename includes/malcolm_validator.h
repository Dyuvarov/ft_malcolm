#ifndef FT_MALCOLM_MALCOLM_VALIDATOR_H
#define FT_MALCOLM_MALCOLM_VALIDATOR_H

#include "libft.h"
#include "ft_status.h"
#include <stdio.h>

int validate_args(int argc, char** argv);
int validate_ip_v4(char const* ip);
int validate_mac(char const* mac);

#endif //FT_MALCOLM_MALCOLM_VALIDATOR_H
